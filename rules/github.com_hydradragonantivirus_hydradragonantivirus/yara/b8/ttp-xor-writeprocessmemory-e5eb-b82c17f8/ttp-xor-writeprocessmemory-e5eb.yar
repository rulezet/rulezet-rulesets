rule TTP_XOR_WriteProcessMemory_e5eb {
  strings:
    $key_e5eb = { b2 99 [2] 80 bb [2] 86 8e [2] a8 8e [2] 97 92 }

  condition:
    any of them
}