rule TTP_XOR_WriteProcessMemory_c7eb {
  strings:
    $key_c7eb = { 90 99 [2] a2 bb [2] a4 8e [2] 8a 8e [2] b5 92 }

  condition:
    any of them
}