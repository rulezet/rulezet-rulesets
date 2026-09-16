rule TTP_XOR_WriteProcessMemory_f767 {
  strings:
    $key_f767 = { a0 15 [2] 92 37 [2] 94 02 [2] ba 02 [2] 85 1e }

  condition:
    any of them
}