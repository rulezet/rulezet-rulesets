rule TTP_XOR_WriteProcessMemory_1984 {
  strings:
    $key_1984 = { 4e f6 [2] 7c d4 [2] 7a e1 [2] 54 e1 [2] 6b fd }

  condition:
    any of them
}