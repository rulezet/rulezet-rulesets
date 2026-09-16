rule TTP_XOR_WriteProcessMemory_96eb {
  strings:
    $key_96eb = { c1 99 [2] f3 bb [2] f5 8e [2] db 8e [2] e4 92 }

  condition:
    any of them
}