rule TTP_XOR_WriteProcessMemory_f096 {
  strings:
    $key_f096 = { a7 e4 [2] 95 c6 [2] 93 f3 [2] bd f3 [2] 82 ef }

  condition:
    any of them
}