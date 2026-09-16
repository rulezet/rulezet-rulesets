rule TTP_XOR_WriteProcessMemory_5984 {
  strings:
    $key_5984 = { 0e f6 [2] 3c d4 [2] 3a e1 [2] 14 e1 [2] 2b fd }

  condition:
    any of them
}