rule TTP_XOR_WriteProcessMemory_55de {
  strings:
    $key_55de = { 02 ac [2] 30 8e [2] 36 bb [2] 18 bb [2] 27 a7 }

  condition:
    any of them
}