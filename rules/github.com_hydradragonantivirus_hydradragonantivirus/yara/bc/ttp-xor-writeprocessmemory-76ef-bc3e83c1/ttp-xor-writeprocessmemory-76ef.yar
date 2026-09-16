rule TTP_XOR_WriteProcessMemory_76ef {
  strings:
    $key_76ef = { 21 9d [2] 13 bf [2] 15 8a [2] 3b 8a [2] 04 96 }

  condition:
    any of them
}