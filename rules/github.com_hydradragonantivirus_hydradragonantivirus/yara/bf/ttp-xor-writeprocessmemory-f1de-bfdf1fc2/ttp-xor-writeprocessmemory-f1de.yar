rule TTP_XOR_WriteProcessMemory_f1de {
  strings:
    $key_f1de = { a6 ac [2] 94 8e [2] 92 bb [2] bc bb [2] 83 a7 }

  condition:
    any of them
}