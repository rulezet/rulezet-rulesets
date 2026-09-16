rule TTP_XOR_WriteProcessMemory_0bde {
  strings:
    $key_0bde = { 5c ac [2] 6e 8e [2] 68 bb [2] 46 bb [2] 79 a7 }

  condition:
    any of them
}