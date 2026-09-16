rule TTP_XOR_WriteProcessMemory_60eb {
  strings:
    $key_60eb = { 37 99 [2] 05 bb [2] 03 8e [2] 2d 8e [2] 12 92 }

  condition:
    any of them
}