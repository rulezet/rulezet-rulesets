rule TTP_XOR_WriteProcessMemory_5bde {
  strings:
    $key_5bde = { 0c ac [2] 3e 8e [2] 38 bb [2] 16 bb [2] 29 a7 }

  condition:
    any of them
}