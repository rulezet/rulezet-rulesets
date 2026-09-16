rule TTP_XOR_WriteProcessMemory_d4de {
  strings:
    $key_d4de = { 83 ac [2] b1 8e [2] b7 bb [2] 99 bb [2] a6 a7 }

  condition:
    any of them
}