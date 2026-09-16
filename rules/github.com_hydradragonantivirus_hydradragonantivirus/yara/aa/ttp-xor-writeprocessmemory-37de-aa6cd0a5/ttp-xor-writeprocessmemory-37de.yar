rule TTP_XOR_WriteProcessMemory_37de {
  strings:
    $key_37de = { 60 ac [2] 52 8e [2] 54 bb [2] 7a bb [2] 45 a7 }

  condition:
    any of them
}