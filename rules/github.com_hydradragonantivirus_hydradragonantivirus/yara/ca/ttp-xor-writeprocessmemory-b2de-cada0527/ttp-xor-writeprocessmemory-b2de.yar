rule TTP_XOR_WriteProcessMemory_b2de {
  strings:
    $key_b2de = { e5 ac [2] d7 8e [2] d1 bb [2] ff bb [2] c0 a7 }

  condition:
    any of them
}