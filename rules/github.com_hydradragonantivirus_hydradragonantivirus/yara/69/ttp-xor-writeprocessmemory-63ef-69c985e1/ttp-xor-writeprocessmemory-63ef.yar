rule TTP_XOR_WriteProcessMemory_63ef {
  strings:
    $key_63ef = { 34 9d [2] 06 bf [2] 00 8a [2] 2e 8a [2] 11 96 }

  condition:
    any of them
}