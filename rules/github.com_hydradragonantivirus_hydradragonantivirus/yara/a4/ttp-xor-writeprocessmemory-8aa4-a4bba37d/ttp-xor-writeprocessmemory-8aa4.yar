rule TTP_XOR_WriteProcessMemory_8aa4 {
  strings:
    $key_8aa4 = { dd d6 [2] ef f4 [2] e9 c1 [2] c7 c1 [2] f8 dd }

  condition:
    any of them
}