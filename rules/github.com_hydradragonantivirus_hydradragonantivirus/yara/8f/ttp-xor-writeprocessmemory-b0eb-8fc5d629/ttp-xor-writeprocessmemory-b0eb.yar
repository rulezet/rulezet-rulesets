rule TTP_XOR_WriteProcessMemory_b0eb {
  strings:
    $key_b0eb = { e7 99 [2] d5 bb [2] d3 8e [2] fd 8e [2] c2 92 }

  condition:
    any of them
}