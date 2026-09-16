rule TTP_XOR_WriteProcessMemory_b5eb {
  strings:
    $key_b5eb = { e2 99 [2] d0 bb [2] d6 8e [2] f8 8e [2] c7 92 }

  condition:
    any of them
}