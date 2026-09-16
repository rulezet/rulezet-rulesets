rule TTP_XOR_WriteProcessMemory_1bde {
  strings:
    $key_1bde = { 4c ac [2] 7e 8e [2] 78 bb [2] 56 bb [2] 69 a7 }

  condition:
    any of them
}