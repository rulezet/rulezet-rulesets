rule TTP_XOR_WriteProcessMemory_f76e {
  strings:
    $key_f76e = { a0 1c [2] 92 3e [2] 94 0b [2] ba 0b [2] 85 17 }

  condition:
    any of them
}