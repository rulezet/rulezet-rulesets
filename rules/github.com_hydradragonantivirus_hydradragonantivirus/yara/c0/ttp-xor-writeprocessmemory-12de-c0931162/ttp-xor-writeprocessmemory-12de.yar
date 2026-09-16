rule TTP_XOR_WriteProcessMemory_12de {
  strings:
    $key_12de = { 45 ac [2] 77 8e [2] 71 bb [2] 5f bb [2] 60 a7 }

  condition:
    any of them
}