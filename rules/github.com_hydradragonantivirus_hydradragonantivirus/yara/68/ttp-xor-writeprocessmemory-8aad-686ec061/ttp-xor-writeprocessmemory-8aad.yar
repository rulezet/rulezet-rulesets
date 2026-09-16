rule TTP_XOR_WriteProcessMemory_8aad {
  strings:
    $key_8aad = { dd df [2] ef fd [2] e9 c8 [2] c7 c8 [2] f8 d4 }

  condition:
    any of them
}