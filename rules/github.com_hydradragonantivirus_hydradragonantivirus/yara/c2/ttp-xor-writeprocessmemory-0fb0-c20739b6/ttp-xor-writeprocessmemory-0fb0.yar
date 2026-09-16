rule TTP_XOR_WriteProcessMemory_0fb0 {
  strings:
    $key_0fb0 = { 58 c2 [2] 6a e0 [2] 6c d5 [2] 42 d5 [2] 7d c9 }

  condition:
    any of them
}