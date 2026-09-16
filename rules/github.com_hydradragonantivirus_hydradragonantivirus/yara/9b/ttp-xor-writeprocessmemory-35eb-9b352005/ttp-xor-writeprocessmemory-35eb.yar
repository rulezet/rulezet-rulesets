rule TTP_XOR_WriteProcessMemory_35eb {
  strings:
    $key_35eb = { 62 99 [2] 50 bb [2] 56 8e [2] 78 8e [2] 47 92 }

  condition:
    any of them
}