rule TTP_XOR_WriteProcessMemory_d9de {
  strings:
    $key_d9de = { 8e ac [2] bc 8e [2] ba bb [2] 94 bb [2] ab a7 }

  condition:
    any of them
}