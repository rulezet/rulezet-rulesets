rule TTP_XOR_WriteProcessMemory_61de {
  strings:
    $key_61de = { 36 ac [2] 04 8e [2] 02 bb [2] 2c bb [2] 13 a7 }

  condition:
    any of them
}