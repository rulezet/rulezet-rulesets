rule TTP_XOR_WriteProcessMemory_1ade {
  strings:
    $key_1ade = { 4d ac [2] 7f 8e [2] 79 bb [2] 57 bb [2] 68 a7 }

  condition:
    any of them
}