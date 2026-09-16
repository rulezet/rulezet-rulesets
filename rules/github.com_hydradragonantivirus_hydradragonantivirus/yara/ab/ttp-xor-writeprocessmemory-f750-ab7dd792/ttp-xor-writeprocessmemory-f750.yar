rule TTP_XOR_WriteProcessMemory_f750 {
  strings:
    $key_f750 = { a0 22 [2] 92 00 [2] 94 35 [2] ba 35 [2] 85 29 }

  condition:
    any of them
}