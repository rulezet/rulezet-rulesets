rule TTP_XOR_WriteProcessMemory_a1eb {
  strings:
    $key_a1eb = { f6 99 [2] c4 bb [2] c2 8e [2] ec 8e [2] d3 92 }

  condition:
    any of them
}