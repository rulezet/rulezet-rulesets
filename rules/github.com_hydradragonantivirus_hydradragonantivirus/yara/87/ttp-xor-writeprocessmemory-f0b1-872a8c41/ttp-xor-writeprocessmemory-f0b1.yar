rule TTP_XOR_WriteProcessMemory_f0b1 {
  strings:
    $key_f0b1 = { a7 c3 [2] 95 e1 [2] 93 d4 [2] bd d4 [2] 82 c8 }

  condition:
    any of them
}