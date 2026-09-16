rule TTP_XOR_WriteProcessMemory_8ade {
  strings:
    $key_8ade = { dd ac [2] ef 8e [2] e9 bb [2] c7 bb [2] f8 a7 }

  condition:
    any of them
}