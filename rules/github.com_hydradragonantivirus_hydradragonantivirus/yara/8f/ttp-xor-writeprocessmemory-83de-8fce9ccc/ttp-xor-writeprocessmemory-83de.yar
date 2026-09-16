rule TTP_XOR_WriteProcessMemory_83de {
  strings:
    $key_83de = { d4 ac [2] e6 8e [2] e0 bb [2] ce bb [2] f1 a7 }

  condition:
    any of them
}