rule TTP_XOR_WriteProcessMemory_85de {
  strings:
    $key_85de = { d2 ac [2] e0 8e [2] e6 bb [2] c8 bb [2] f7 a7 }

  condition:
    any of them
}