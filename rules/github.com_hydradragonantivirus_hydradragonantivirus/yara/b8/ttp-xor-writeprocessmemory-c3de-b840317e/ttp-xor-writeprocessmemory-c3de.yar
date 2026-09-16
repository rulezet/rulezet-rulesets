rule TTP_XOR_WriteProcessMemory_c3de {
  strings:
    $key_c3de = { 94 ac [2] a6 8e [2] a0 bb [2] 8e bb [2] b1 a7 }

  condition:
    any of them
}