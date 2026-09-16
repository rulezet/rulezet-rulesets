rule TTP_XOR_WriteProcessMemory_39de {
  strings:
    $key_39de = { 6e ac [2] 5c 8e [2] 5a bb [2] 74 bb [2] 4b a7 }

  condition:
    any of them
}