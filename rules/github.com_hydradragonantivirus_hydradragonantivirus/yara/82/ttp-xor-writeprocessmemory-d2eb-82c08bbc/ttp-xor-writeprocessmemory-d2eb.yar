rule TTP_XOR_WriteProcessMemory_d2eb {
  strings:
    $key_d2eb = { 85 99 [2] b7 bb [2] b1 8e [2] 9f 8e [2] a0 92 }

  condition:
    any of them
}