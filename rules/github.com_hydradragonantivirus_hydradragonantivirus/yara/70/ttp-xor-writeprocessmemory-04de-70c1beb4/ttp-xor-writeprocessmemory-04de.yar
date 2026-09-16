rule TTP_XOR_WriteProcessMemory_04de {
  strings:
    $key_04de = { 53 ac [2] 61 8e [2] 67 bb [2] 49 bb [2] 76 a7 }

  condition:
    any of them
}