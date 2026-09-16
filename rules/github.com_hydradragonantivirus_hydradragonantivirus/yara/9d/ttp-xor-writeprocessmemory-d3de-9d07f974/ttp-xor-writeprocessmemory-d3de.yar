rule TTP_XOR_WriteProcessMemory_d3de {
  strings:
    $key_d3de = { 84 ac [2] b6 8e [2] b0 bb [2] 9e bb [2] a1 a7 }

  condition:
    any of them
}