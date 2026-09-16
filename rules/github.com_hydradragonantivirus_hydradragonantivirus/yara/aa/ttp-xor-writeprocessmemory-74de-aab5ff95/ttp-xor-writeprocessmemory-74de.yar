rule TTP_XOR_WriteProcessMemory_74de {
  strings:
    $key_74de = { 23 ac [2] 11 8e [2] 17 bb [2] 39 bb [2] 06 a7 }

  condition:
    any of them
}