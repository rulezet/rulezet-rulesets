rule TTP_XOR_WriteProcessMemory_3bde {
  strings:
    $key_3bde = { 6c ac [2] 5e 8e [2] 58 bb [2] 76 bb [2] 49 a7 }

  condition:
    any of them
}