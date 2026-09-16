rule TTP_XOR_WriteProcessMemory_f0b0 {
  strings:
    $key_f0b0 = { a7 c2 [2] 95 e0 [2] 93 d5 [2] bd d5 [2] 82 c9 }

  condition:
    any of them
}