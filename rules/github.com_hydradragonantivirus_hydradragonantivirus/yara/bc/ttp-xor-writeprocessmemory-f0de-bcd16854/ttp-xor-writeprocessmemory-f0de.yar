rule TTP_XOR_WriteProcessMemory_f0de {
  strings:
    $key_f0de = { a7 ac [2] 95 8e [2] 93 bb [2] bd bb [2] 82 a7 }

  condition:
    any of them
}