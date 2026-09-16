rule TTP_XOR_WriteProcessMemory_b0de {
  strings:
    $key_b0de = { e7 ac [2] d5 8e [2] d3 bb [2] fd bb [2] c2 a7 }

  condition:
    any of them
}