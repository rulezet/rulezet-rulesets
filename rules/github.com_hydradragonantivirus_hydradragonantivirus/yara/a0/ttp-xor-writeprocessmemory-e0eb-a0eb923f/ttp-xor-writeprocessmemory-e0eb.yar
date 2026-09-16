rule TTP_XOR_WriteProcessMemory_e0eb {
  strings:
    $key_e0eb = { b7 99 [2] 85 bb [2] 83 8e [2] ad 8e [2] 92 92 }

  condition:
    any of them
}