rule TTP_XOR_WriteProcessMemory_3984 {
  strings:
    $key_3984 = { 6e f6 [2] 5c d4 [2] 5a e1 [2] 74 e1 [2] 4b fd }

  condition:
    any of them
}