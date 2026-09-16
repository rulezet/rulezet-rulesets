rule TTP_XOR_WriteProcessMemory_17de {
  strings:
    $key_17de = { 40 ac [2] 72 8e [2] 74 bb [2] 5a bb [2] 65 a7 }

  condition:
    any of them
}