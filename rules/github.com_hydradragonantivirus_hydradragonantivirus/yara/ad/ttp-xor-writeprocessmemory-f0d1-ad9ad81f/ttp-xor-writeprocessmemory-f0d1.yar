rule TTP_XOR_WriteProcessMemory_f0d1 {
  strings:
    $key_f0d1 = { a7 a3 [2] 95 81 [2] 93 b4 [2] bd b4 [2] 82 a8 }

  condition:
    any of them
}