rule TTP_XOR_WriteProcessMemory_4ade {
  strings:
    $key_4ade = { 1d ac [2] 2f 8e [2] 29 bb [2] 07 bb [2] 38 a7 }

  condition:
    any of them
}