rule TTP_XOR_WriteProcessMemory_32de {
  strings:
    $key_32de = { 65 ac [2] 57 8e [2] 51 bb [2] 7f bb [2] 40 a7 }

  condition:
    any of them
}