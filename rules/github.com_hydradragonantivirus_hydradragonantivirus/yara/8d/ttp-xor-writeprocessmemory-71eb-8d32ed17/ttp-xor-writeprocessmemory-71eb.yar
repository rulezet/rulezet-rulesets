rule TTP_XOR_WriteProcessMemory_71eb {
  strings:
    $key_71eb = { 26 99 [2] 14 bb [2] 12 8e [2] 3c 8e [2] 03 92 }

  condition:
    any of them
}