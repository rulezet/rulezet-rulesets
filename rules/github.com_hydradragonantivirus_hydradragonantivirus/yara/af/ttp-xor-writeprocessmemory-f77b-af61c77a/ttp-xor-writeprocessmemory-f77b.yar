rule TTP_XOR_WriteProcessMemory_f77b {
  strings:
    $key_f77b = { a0 09 [2] 92 2b [2] 94 1e [2] ba 1e [2] 85 02 }

  condition:
    any of them
}