rule TTP_XOR_WriteProcessMemory_66eb {
  strings:
    $key_66eb = { 31 99 [2] 03 bb [2] 05 8e [2] 2b 8e [2] 14 92 }

  condition:
    any of them
}