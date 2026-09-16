rule TTP_XOR_WriteProcessMemory_f76c {
  strings:
    $key_f76c = { a0 1e [2] 92 3c [2] 94 09 [2] ba 09 [2] 85 15 }

  condition:
    any of them
}