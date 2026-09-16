rule TTP_XOR_WriteProcessMemory_c7de {
  strings:
    $key_c7de = { 90 ac [2] a2 8e [2] a4 bb [2] 8a bb [2] b5 a7 }

  condition:
    any of them
}