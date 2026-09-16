rule TTP_XOR_WriteProcessMemory_93de {
  strings:
    $key_93de = { c4 ac [2] f6 8e [2] f0 bb [2] de bb [2] e1 a7 }

  condition:
    any of them
}