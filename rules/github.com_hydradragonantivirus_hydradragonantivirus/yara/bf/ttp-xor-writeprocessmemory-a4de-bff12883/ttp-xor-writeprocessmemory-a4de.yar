rule TTP_XOR_WriteProcessMemory_a4de {
  strings:
    $key_a4de = { f3 ac [2] c1 8e [2] c7 bb [2] e9 bb [2] d6 a7 }

  condition:
    any of them
}