rule TTP_XOR_WriteProcessMemory_14eb {
  strings:
    $key_14eb = { 43 99 [2] 71 bb [2] 77 8e [2] 59 8e [2] 66 92 }

  condition:
    any of them
}