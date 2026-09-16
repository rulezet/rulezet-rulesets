rule TTP_XOR_WriteProcessMemory_f74e {
  strings:
    $key_f74e = { a0 3c [2] 92 1e [2] 94 2b [2] ba 2b [2] 85 37 }

  condition:
    any of them
}