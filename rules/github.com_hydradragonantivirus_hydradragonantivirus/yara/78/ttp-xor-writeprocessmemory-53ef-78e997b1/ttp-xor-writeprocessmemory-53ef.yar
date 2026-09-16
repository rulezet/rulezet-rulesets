rule TTP_XOR_WriteProcessMemory_53ef {
  strings:
    $key_53ef = { 04 9d [2] 36 bf [2] 30 8a [2] 1e 8a [2] 21 96 }

  condition:
    any of them
}