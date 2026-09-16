rule TTP_XOR_WriteProcessMemory_f5de {
  strings:
    $key_f5de = { a2 ac [2] 90 8e [2] 96 bb [2] b8 bb [2] 87 a7 }

  condition:
    any of them
}