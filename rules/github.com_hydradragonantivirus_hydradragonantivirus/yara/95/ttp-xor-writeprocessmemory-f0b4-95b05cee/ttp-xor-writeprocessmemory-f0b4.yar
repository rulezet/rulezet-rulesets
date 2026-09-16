rule TTP_XOR_WriteProcessMemory_f0b4 {
  strings:
    $key_f0b4 = { a7 c6 [2] 95 e4 [2] 93 d1 [2] bd d1 [2] 82 cd }

  condition:
    any of them
}