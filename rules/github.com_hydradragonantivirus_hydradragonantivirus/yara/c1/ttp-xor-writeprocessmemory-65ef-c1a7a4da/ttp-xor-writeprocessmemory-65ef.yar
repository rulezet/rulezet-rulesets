rule TTP_XOR_WriteProcessMemory_65ef {
  strings:
    $key_65ef = { 32 9d [2] 00 bf [2] 06 8a [2] 28 8a [2] 17 96 }

  condition:
    any of them
}