rule TTP_XOR_WriteProcessMemory_f6b0 {
  strings:
    $key_f6b0 = { a1 c2 [2] 93 e0 [2] 95 d5 [2] bb d5 [2] 84 c9 }

  condition:
    any of them
}