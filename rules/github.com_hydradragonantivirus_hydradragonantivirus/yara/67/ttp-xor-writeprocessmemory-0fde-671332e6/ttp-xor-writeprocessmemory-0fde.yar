rule TTP_XOR_WriteProcessMemory_0fde {
  strings:
    $key_0fde = { 58 ac [2] 6a 8e [2] 6c bb [2] 42 bb [2] 7d a7 }

  condition:
    any of them
}