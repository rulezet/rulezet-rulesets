rule TTP_XOR_WriteProcessMemory_f7eb {
  strings:
    $key_f7eb = { a0 99 [2] 92 bb [2] 94 8e [2] ba 8e [2] 85 92 }

  condition:
    any of them
}