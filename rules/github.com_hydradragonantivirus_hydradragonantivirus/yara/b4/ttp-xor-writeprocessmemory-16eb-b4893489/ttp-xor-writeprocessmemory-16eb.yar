rule TTP_XOR_WriteProcessMemory_16eb {
  strings:
    $key_16eb = { 41 99 [2] 73 bb [2] 75 8e [2] 5b 8e [2] 64 92 }

  condition:
    any of them
}