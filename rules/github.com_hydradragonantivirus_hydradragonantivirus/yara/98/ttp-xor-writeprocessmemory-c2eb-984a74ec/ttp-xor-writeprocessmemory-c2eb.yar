rule TTP_XOR_WriteProcessMemory_c2eb {
  strings:
    $key_c2eb = { 95 99 [2] a7 bb [2] a1 8e [2] 8f 8e [2] b0 92 }

  condition:
    any of them
}