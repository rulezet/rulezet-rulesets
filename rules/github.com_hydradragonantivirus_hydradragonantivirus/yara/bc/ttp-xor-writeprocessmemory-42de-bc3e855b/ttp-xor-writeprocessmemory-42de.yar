rule TTP_XOR_WriteProcessMemory_42de {
  strings:
    $key_42de = { 15 ac [2] 27 8e [2] 21 bb [2] 0f bb [2] 30 a7 }

  condition:
    any of them
}