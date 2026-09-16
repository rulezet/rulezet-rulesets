rule TTP_XOR_WriteProcessMemory_f74b {
  strings:
    $key_f74b = { a0 39 [2] 92 1b [2] 94 2e [2] ba 2e [2] 85 32 }

  condition:
    any of them
}