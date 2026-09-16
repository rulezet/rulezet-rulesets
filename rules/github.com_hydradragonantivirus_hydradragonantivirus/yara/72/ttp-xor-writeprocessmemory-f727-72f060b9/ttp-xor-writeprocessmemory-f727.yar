rule TTP_XOR_WriteProcessMemory_f727 {
  strings:
    $key_f727 = { a0 55 [2] 92 77 [2] 94 42 [2] ba 42 [2] 85 5e }

  condition:
    any of them
}