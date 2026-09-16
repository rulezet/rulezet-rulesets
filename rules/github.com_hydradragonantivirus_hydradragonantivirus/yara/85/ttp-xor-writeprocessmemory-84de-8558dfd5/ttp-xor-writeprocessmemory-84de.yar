rule TTP_XOR_WriteProcessMemory_84de {
  strings:
    $key_84de = { d3 ac [2] e1 8e [2] e7 bb [2] c9 bb [2] f6 a7 }

  condition:
    any of them
}