rule TTP_XOR_WriteProcessMemory_d7de {
  strings:
    $key_d7de = { 80 ac [2] b2 8e [2] b4 bb [2] 9a bb [2] a5 a7 }

  condition:
    any of them
}