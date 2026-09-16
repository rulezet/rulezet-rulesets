rule TTP_XOR_WriteProcessMemory_75de {
  strings:
    $key_75de = { 22 ac [2] 10 8e [2] 16 bb [2] 38 bb [2] 07 a7 }

  condition:
    any of them
}