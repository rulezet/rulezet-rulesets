rule TTP_XOR_WriteProcessMemory_45eb {
  strings:
    $key_45eb = { 12 99 [2] 20 bb [2] 26 8e [2] 08 8e [2] 37 92 }

  condition:
    any of them
}