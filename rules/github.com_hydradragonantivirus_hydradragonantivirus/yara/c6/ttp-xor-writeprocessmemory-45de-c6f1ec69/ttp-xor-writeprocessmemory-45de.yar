rule TTP_XOR_WriteProcessMemory_45de {
  strings:
    $key_45de = { 12 ac [2] 20 8e [2] 26 bb [2] 08 bb [2] 37 a7 }

  condition:
    any of them
}