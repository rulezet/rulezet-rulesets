rule TTP_XOR_WriteProcessMemory_34de {
  strings:
    $key_34de = { 63 ac [2] 51 8e [2] 57 bb [2] 79 bb [2] 46 a7 }

  condition:
    any of them
}