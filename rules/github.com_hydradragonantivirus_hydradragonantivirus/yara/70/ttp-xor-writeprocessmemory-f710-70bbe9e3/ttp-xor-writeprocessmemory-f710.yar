rule TTP_XOR_WriteProcessMemory_f710 {
  strings:
    $key_f710 = { a0 62 [2] 92 40 [2] 94 75 [2] ba 75 [2] 85 69 }

  condition:
    any of them
}