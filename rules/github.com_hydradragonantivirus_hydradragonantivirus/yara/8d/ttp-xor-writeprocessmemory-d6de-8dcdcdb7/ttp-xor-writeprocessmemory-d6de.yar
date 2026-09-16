rule TTP_XOR_WriteProcessMemory_d6de {
  strings:
    $key_d6de = { 81 ac [2] b3 8e [2] b5 bb [2] 9b bb [2] a4 a7 }

  condition:
    any of them
}