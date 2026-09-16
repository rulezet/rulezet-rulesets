rule TTP_XOR_WriteProcessMemory_77eb {
  strings:
    $key_77eb = { 20 99 [2] 12 bb [2] 14 8e [2] 3a 8e [2] 05 92 }

  condition:
    any of them
}