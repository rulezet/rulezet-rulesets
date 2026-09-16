rule TTP_XOR_WriteProcessMemory_20eb {
  strings:
    $key_20eb = { 77 99 [2] 45 bb [2] 43 8e [2] 6d 8e [2] 52 92 }

  condition:
    any of them
}