rule TTP_XOR_WriteProcessMemory_46de {
  strings:
    $key_46de = { 11 ac [2] 23 8e [2] 25 bb [2] 0b bb [2] 34 a7 }

  condition:
    any of them
}