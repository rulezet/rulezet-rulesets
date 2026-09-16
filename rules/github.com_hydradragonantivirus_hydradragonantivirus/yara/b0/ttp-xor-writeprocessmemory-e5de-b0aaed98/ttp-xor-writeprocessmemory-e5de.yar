rule TTP_XOR_WriteProcessMemory_e5de {
  strings:
    $key_e5de = { b2 ac [2] 80 8e [2] 86 bb [2] a8 bb [2] 97 a7 }

  condition:
    any of them
}