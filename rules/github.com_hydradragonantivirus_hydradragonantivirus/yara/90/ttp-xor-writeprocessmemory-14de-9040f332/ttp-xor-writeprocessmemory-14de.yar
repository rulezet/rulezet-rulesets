rule TTP_XOR_WriteProcessMemory_14de {
  strings:
    $key_14de = { 43 ac [2] 71 8e [2] 77 bb [2] 59 bb [2] 66 a7 }

  condition:
    any of them
}