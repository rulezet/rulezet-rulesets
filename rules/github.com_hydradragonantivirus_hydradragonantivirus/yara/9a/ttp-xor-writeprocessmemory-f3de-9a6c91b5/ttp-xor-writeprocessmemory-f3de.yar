rule TTP_XOR_WriteProcessMemory_f3de {
  strings:
    $key_f3de = { a4 ac [2] 96 8e [2] 90 bb [2] be bb [2] 81 a7 }

  condition:
    any of them
}