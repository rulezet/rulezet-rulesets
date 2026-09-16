rule TTP_XOR_WriteProcessMemory_f772 {
  strings:
    $key_f772 = { a0 00 [2] 92 22 [2] 94 17 [2] ba 17 [2] 85 0b }

  condition:
    any of them
}