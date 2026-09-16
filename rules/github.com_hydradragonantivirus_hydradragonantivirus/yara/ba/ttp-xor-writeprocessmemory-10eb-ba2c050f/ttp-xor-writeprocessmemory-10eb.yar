rule TTP_XOR_WriteProcessMemory_10eb {
  strings:
    $key_10eb = { 47 99 [2] 75 bb [2] 73 8e [2] 5d 8e [2] 62 92 }

  condition:
    any of them
}