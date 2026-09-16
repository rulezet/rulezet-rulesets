rule TTP_XOR_WriteProcessMemory_7ade {
  strings:
    $key_7ade = { 2d ac [2] 1f 8e [2] 19 bb [2] 37 bb [2] 08 a7 }

  condition:
    any of them
}