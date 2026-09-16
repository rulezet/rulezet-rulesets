rule TTP_XOR_WriteProcessMemory_e6eb {
  strings:
    $key_e6eb = { b1 99 [2] 83 bb [2] 85 8e [2] ab 8e [2] 94 92 }

  condition:
    any of them
}