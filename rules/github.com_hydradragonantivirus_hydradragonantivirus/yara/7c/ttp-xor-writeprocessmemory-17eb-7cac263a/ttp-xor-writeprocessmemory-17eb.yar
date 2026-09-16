rule TTP_XOR_WriteProcessMemory_17eb {
  strings:
    $key_17eb = { 40 99 [2] 72 bb [2] 74 8e [2] 5a 8e [2] 65 92 }

  condition:
    any of them
}