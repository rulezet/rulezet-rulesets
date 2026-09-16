rule TTP_XOR_WriteProcessMemory_f0eb {
  strings:
    $key_f0eb = { a7 99 [2] 95 bb [2] 93 8e [2] bd 8e [2] 82 92 }

  condition:
    any of them
}