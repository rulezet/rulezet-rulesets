rule TTP_XOR_WriteProcessMemory_37eb {
  strings:
    $key_37eb = { 60 99 [2] 52 bb [2] 54 8e [2] 7a 8e [2] 45 92 }

  condition:
    any of them
}