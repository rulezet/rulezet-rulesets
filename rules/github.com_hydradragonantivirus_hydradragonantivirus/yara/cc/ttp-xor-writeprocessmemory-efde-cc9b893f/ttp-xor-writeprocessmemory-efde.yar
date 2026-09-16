rule TTP_XOR_WriteProcessMemory_efde {
  strings:
    $key_efde = { b8 ac [2] 8a 8e [2] 8c bb [2] a2 bb [2] 9d a7 }

  condition:
    any of them
}