rule TTP_XOR_WriteProcessMemory_47de {
  strings:
    $key_47de = { 10 ac [2] 22 8e [2] 24 bb [2] 0a bb [2] 35 a7 }

  condition:
    any of them
}