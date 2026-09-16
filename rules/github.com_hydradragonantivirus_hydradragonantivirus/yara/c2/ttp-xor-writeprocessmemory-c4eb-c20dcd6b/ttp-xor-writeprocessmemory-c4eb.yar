rule TTP_XOR_WriteProcessMemory_c4eb {
  strings:
    $key_c4eb = { 93 99 [2] a1 bb [2] a7 8e [2] 89 8e [2] b6 92 }

  condition:
    any of them
}