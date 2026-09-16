rule TTP_XOR_WriteProcessMemory_04ef {
  strings:
    $key_04ef = { 53 9d [2] 61 bf [2] 67 8a [2] 49 8a [2] 76 96 }

  condition:
    any of them
}