rule TTP_XOR_WriteProcessMemory_eade {
  strings:
    $key_eade = { bd ac [2] 8f 8e [2] 89 bb [2] a7 bb [2] 98 a7 }

  condition:
    any of them
}