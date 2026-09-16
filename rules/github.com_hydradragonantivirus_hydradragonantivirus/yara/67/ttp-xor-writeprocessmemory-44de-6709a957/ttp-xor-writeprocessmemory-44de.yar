rule TTP_XOR_WriteProcessMemory_44de {
  strings:
    $key_44de = { 13 ac [2] 21 8e [2] 27 bb [2] 09 bb [2] 36 a7 }

  condition:
    any of them
}