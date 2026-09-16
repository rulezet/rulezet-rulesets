rule TTP_XOR_WriteProcessMemory_f2de {
  strings:
    $key_f2de = { a5 ac [2] 97 8e [2] 91 bb [2] bf bb [2] 80 a7 }

  condition:
    any of them
}