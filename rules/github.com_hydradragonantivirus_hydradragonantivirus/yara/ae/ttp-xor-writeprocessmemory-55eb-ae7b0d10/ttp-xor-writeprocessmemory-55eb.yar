rule TTP_XOR_WriteProcessMemory_55eb {
  strings:
    $key_55eb = { 02 99 [2] 30 bb [2] 36 8e [2] 18 8e [2] 27 92 }

  condition:
    any of them
}