rule TTP_XOR_WriteProcessMemory_3fde {
  strings:
    $key_3fde = { 68 ac [2] 5a 8e [2] 5c bb [2] 72 bb [2] 4d a7 }

  condition:
    any of them
}