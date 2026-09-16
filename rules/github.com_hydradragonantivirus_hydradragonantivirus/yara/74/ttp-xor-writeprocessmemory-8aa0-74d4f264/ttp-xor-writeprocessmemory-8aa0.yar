rule TTP_XOR_WriteProcessMemory_8aa0 {
  strings:
    $key_8aa0 = { dd d2 [2] ef f0 [2] e9 c5 [2] c7 c5 [2] f8 d9 }

  condition:
    any of them
}