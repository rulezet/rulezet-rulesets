rule TTP_XOR_WriteProcessMemory_06ef {
  strings:
    $key_06ef = { 51 9d [2] 63 bf [2] 65 8a [2] 4b 8a [2] 74 96 }

  condition:
    any of them
}