rule TTP_XOR_WriteProcessMemory_f75e {
  strings:
    $key_f75e = { a0 2c [2] 92 0e [2] 94 3b [2] ba 3b [2] 85 27 }

  condition:
    any of them
}