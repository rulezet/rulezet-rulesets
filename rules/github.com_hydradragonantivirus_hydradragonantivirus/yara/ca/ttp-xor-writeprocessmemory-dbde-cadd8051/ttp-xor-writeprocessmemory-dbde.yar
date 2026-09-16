rule TTP_XOR_WriteProcessMemory_dbde {
  strings:
    $key_dbde = { 8c ac [2] be 8e [2] b8 bb [2] 96 bb [2] a9 a7 }

  condition:
    any of them
}