rule TTP_XOR_WriteProcessMemory_05de {
  strings:
    $key_05de = { 52 ac [2] 60 8e [2] 66 bb [2] 48 bb [2] 77 a7 }

  condition:
    any of them
}