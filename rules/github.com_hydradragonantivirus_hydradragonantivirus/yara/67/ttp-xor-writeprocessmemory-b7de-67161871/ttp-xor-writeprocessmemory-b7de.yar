rule TTP_XOR_WriteProcessMemory_b7de {
  strings:
    $key_b7de = { e0 ac [2] d2 8e [2] d4 bb [2] fa bb [2] c5 a7 }

  condition:
    any of them
}