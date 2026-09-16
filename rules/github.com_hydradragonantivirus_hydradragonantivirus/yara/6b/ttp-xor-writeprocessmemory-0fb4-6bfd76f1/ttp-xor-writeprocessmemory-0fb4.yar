rule TTP_XOR_WriteProcessMemory_0fb4 {
  strings:
    $key_0fb4 = { 58 c6 [2] 6a e4 [2] 6c d1 [2] 42 d1 [2] 7d cd }

  condition:
    any of them
}