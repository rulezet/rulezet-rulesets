rule TTP_XOR_WriteProcessMemory_a6de {
  strings:
    $key_a6de = { f1 ac [2] c3 8e [2] c5 bb [2] eb bb [2] d4 a7 }

  condition:
    any of them
}