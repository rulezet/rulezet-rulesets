rule TTP_XOR_WriteProcessMemory_f0d6 {
  strings:
    $key_f0d6 = { a7 a4 [2] 95 86 [2] 93 b3 [2] bd b3 [2] 82 af }

  condition:
    any of them
}