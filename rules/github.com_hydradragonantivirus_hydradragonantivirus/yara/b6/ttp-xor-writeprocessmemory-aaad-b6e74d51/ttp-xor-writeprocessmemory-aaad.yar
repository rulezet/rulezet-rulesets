rule TTP_XOR_WriteProcessMemory_aaad {
  strings:
    $key_aaad = { fd df [2] cf fd [2] c9 c8 [2] e7 c8 [2] d8 d4 }

  condition:
    any of them
}