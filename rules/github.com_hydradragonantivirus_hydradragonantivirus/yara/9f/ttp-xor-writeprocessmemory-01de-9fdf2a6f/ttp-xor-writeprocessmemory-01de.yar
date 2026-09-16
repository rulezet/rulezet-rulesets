rule TTP_XOR_WriteProcessMemory_01de {
  strings:
    $key_01de = { 56 ac [2] 64 8e [2] 62 bb [2] 4c bb [2] 73 a7 }

  condition:
    any of them
}