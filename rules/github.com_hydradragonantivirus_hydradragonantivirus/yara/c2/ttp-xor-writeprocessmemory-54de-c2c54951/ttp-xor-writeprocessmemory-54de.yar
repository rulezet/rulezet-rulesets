rule TTP_XOR_WriteProcessMemory_54de {
  strings:
    $key_54de = { 03 ac [2] 31 8e [2] 37 bb [2] 19 bb [2] 26 a7 }

  condition:
    any of them
}