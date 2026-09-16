rule TTP_XOR_WriteProcessMemory_02ef {
  strings:
    $key_02ef = { 55 9d [2] 67 bf [2] 61 8a [2] 4f 8a [2] 70 96 }

  condition:
    any of them
}