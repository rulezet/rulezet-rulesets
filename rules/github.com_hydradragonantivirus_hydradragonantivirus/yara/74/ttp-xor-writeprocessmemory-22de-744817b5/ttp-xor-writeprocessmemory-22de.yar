rule TTP_XOR_WriteProcessMemory_22de {
  strings:
    $key_22de = { 75 ac [2] 47 8e [2] 41 bb [2] 6f bb [2] 50 a7 }

  condition:
    any of them
}