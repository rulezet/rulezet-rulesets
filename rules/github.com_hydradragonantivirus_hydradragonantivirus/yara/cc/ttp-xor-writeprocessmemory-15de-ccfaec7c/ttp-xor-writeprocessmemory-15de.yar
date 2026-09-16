rule TTP_XOR_WriteProcessMemory_15de {
  strings:
    $key_15de = { 42 ac [2] 70 8e [2] 76 bb [2] 58 bb [2] 67 a7 }

  condition:
    any of them
}