rule TTP_XOR_WriteProcessMemory_4cad {
  strings:
    $key_4cad = { 1b df [2] 29 fd [2] 2f c8 [2] 01 c8 [2] 3e d4 }

  condition:
    any of them
}