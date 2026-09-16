rule TTP_XOR_WriteProcessMemory_80eb {
  strings:
    $key_80eb = { d7 99 [2] e5 bb [2] e3 8e [2] cd 8e [2] f2 92 }

  condition:
    any of them
}