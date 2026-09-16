rule TTP_XOR_WriteProcessMemory_73eb {
  strings:
    $key_73eb = { 24 99 [2] 16 bb [2] 10 8e [2] 3e 8e [2] 01 92 }

  condition:
    any of them
}