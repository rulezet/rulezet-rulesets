rule TTP_XOR_WriteProcessMemory_74ef {
  strings:
    $key_74ef = { 23 9d [2] 11 bf [2] 17 8a [2] 39 8a [2] 06 96 }

  condition:
    any of them
}