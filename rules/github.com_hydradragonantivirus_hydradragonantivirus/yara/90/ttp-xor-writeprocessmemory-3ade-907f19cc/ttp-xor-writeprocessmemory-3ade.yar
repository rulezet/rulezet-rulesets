rule TTP_XOR_WriteProcessMemory_3ade {
  strings:
    $key_3ade = { 6d ac [2] 5f 8e [2] 59 bb [2] 77 bb [2] 48 a7 }

  condition:
    any of them
}