rule TTP_XOR_WriteProcessMemory_2ade {
  strings:
    $key_2ade = { 7d ac [2] 4f 8e [2] 49 bb [2] 67 bb [2] 58 a7 }

  condition:
    any of them
}