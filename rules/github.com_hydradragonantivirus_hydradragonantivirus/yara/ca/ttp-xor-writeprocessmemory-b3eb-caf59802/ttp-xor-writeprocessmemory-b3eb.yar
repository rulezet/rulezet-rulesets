rule TTP_XOR_WriteProcessMemory_b3eb {
  strings:
    $key_b3eb = { e4 99 [2] d6 bb [2] d0 8e [2] fe 8e [2] c1 92 }

  condition:
    any of them
}