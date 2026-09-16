rule TTP_XOR_WriteProcessMemory_f76b {
  strings:
    $key_f76b = { a0 19 [2] 92 3b [2] 94 0e [2] ba 0e [2] 85 12 }

  condition:
    any of them
}