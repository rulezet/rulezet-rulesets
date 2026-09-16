rule TTP_XOR_WriteProcessMemory_d1de {
  strings:
    $key_d1de = { 86 ac [2] b4 8e [2] b2 bb [2] 9c bb [2] a3 a7 }

  condition:
    any of them
}