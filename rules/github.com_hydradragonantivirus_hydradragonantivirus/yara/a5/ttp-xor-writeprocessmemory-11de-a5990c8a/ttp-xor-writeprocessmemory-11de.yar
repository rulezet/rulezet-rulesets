rule TTP_XOR_WriteProcessMemory_11de {
  strings:
    $key_11de = { 46 ac [2] 74 8e [2] 72 bb [2] 5c bb [2] 63 a7 }

  condition:
    any of them
}