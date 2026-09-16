rule TTP_XOR_WriteProcessMemory_03eb {
  strings:
    $key_03eb = { 54 99 [2] 66 bb [2] 60 8e [2] 4e 8e [2] 71 92 }

  condition:
    any of them
}