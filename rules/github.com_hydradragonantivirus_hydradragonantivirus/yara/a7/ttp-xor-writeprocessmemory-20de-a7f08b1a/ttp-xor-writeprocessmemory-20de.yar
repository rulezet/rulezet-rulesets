rule TTP_XOR_WriteProcessMemory_20de {
  strings:
    $key_20de = { 77 ac [2] 45 8e [2] 43 bb [2] 6d bb [2] 52 a7 }

  condition:
    any of them
}