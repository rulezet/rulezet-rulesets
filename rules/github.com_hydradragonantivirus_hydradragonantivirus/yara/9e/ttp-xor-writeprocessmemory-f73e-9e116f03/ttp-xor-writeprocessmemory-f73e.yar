rule TTP_XOR_WriteProcessMemory_f73e {
  strings:
    $key_f73e = { a0 4c [2] 92 6e [2] 94 5b [2] ba 5b [2] 85 47 }

  condition:
    any of them
}