rule TTP_XOR_WriteProcessMemory_86de {
  strings:
    $key_86de = { d1 ac [2] e3 8e [2] e5 bb [2] cb bb [2] f4 a7 }

  condition:
    any of them
}