rule TTP_XOR_WriteProcessMemory_f765 {
  strings:
    $key_f765 = { a0 17 [2] 92 35 [2] 94 00 [2] ba 00 [2] 85 1c }

  condition:
    any of them
}