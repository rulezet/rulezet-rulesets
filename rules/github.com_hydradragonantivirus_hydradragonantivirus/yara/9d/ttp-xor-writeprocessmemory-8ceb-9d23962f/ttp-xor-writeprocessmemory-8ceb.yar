rule TTP_XOR_WriteProcessMemory_8ceb {
  strings:
    $key_8ceb = { db 99 [2] e9 bb [2] ef 8e [2] c1 8e [2] fe 92 }

  condition:
    any of them
}