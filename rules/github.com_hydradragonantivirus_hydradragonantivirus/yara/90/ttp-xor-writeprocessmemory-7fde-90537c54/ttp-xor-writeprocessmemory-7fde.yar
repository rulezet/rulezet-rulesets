rule TTP_XOR_WriteProcessMemory_7fde {
  strings:
    $key_7fde = { 28 ac [2] 1a 8e [2] 1c bb [2] 32 bb [2] 0d a7 }

  condition:
    any of them
}