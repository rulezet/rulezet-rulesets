rule TTP_XOR_WriteProcessMemory_c2de {
  strings:
    $key_c2de = { 95 ac [2] a7 8e [2] a1 bb [2] 8f bb [2] b0 a7 }

  condition:
    any of them
}