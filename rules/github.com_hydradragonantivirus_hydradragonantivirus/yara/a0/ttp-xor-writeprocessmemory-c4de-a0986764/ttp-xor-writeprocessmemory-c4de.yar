rule TTP_XOR_WriteProcessMemory_c4de {
  strings:
    $key_c4de = { 93 ac [2] a1 8e [2] a7 bb [2] 89 bb [2] b6 a7 }

  condition:
    any of them
}