rule TTP_XOR_WriteProcessMemory_0fb1 {
  strings:
    $key_0fb1 = { 58 c3 [2] 6a e1 [2] 6c d4 [2] 42 d4 [2] 7d c8 }

  condition:
    any of them
}