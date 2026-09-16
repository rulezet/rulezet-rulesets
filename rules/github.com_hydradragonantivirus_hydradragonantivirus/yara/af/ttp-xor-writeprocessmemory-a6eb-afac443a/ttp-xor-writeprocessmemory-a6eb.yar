rule TTP_XOR_WriteProcessMemory_a6eb {
  strings:
    $key_a6eb = { f1 99 [2] c3 bb [2] c5 8e [2] eb 8e [2] d4 92 }

  condition:
    any of them
}