rule TTP_XOR_WriteProcessMemory_24de {
  strings:
    $key_24de = { 73 ac [2] 41 8e [2] 47 bb [2] 69 bb [2] 56 a7 }

  condition:
    any of them
}