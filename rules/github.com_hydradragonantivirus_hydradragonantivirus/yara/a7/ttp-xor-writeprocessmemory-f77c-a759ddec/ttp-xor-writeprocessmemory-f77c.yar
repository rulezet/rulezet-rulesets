rule TTP_XOR_WriteProcessMemory_f77c {
  strings:
    $key_f77c = { a0 0e [2] 92 2c [2] 94 19 [2] ba 19 [2] 85 05 }

  condition:
    any of them
}