rule TTP_XOR_WriteProcessMemory_2bde {
  strings:
    $key_2bde = { 7c ac [2] 4e 8e [2] 48 bb [2] 66 bb [2] 59 a7 }

  condition:
    any of them
}