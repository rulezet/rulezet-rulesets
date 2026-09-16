rule TTP_XOR_WriteProcessMemory_64de {
  strings:
    $key_64de = { 33 ac [2] 01 8e [2] 07 bb [2] 29 bb [2] 16 a7 }

  condition:
    any of them
}