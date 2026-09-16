rule TTP_XOR_WriteProcessMemory_12eb {
  strings:
    $key_12eb = { 45 99 [2] 77 bb [2] 71 8e [2] 5f 8e [2] 60 92 }

  condition:
    any of them
}