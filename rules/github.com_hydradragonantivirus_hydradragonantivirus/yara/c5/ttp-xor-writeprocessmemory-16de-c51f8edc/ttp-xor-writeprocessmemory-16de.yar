rule TTP_XOR_WriteProcessMemory_16de {
  strings:
    $key_16de = { 41 ac [2] 73 8e [2] 75 bb [2] 5b bb [2] 64 a7 }

  condition:
    any of them
}