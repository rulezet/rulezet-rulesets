rule TTP_XOR_WriteProcessMemory_f6b1 {
  strings:
    $key_f6b1 = { a1 c3 [2] 93 e1 [2] 95 d4 [2] bb d4 [2] 84 c8 }

  condition:
    any of them
}