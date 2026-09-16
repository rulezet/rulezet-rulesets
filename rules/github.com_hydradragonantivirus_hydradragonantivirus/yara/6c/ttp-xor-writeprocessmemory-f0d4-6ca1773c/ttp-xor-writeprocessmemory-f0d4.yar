rule TTP_XOR_WriteProcessMemory_f0d4 {
  strings:
    $key_f0d4 = { a7 a6 [2] 95 84 [2] 93 b1 [2] bd b1 [2] 82 ad }

  condition:
    any of them
}