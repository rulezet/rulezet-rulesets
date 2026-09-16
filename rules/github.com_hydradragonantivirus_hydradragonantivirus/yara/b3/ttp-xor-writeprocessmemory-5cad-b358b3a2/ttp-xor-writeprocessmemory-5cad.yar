rule TTP_XOR_WriteProcessMemory_5cad {
  strings:
    $key_5cad = { 0b df [2] 39 fd [2] 3f c8 [2] 11 c8 [2] 2e d4 }

  condition:
    any of them
}