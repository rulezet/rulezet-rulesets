rule TTP_XOR_WriteProcessMemory_21de {
  strings:
    $key_21de = { 76 ac [2] 44 8e [2] 42 bb [2] 6c bb [2] 53 a7 }

  condition:
    any of them
}