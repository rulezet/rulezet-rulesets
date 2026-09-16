rule TTP_XOR_WriteProcessMemory_c3eb {
  strings:
    $key_c3eb = { 94 99 [2] a6 bb [2] a0 8e [2] 8e 8e [2] b1 92 }

  condition:
    any of them
}