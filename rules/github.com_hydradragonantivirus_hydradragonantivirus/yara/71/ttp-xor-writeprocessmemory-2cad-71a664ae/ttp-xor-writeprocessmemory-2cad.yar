rule TTP_XOR_WriteProcessMemory_2cad {
  strings:
    $key_2cad = { 7b df [2] 49 fd [2] 4f c8 [2] 61 c8 [2] 5e d4 }

  condition:
    any of them
}