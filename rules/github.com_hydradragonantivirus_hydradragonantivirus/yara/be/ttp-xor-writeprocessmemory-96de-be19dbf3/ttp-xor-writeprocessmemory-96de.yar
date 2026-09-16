rule TTP_XOR_WriteProcessMemory_96de {
  strings:
    $key_96de = { c1 ac [2] f3 8e [2] f5 bb [2] db bb [2] e4 a7 }

  condition:
    any of them
}