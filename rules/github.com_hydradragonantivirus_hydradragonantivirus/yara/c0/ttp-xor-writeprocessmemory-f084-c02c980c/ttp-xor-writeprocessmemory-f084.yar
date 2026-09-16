rule TTP_XOR_WriteProcessMemory_f084 {
  strings:
    $key_f084 = { a7 f6 [2] 95 d4 [2] 93 e1 [2] bd e1 [2] 82 fd }

  condition:
    any of them
}