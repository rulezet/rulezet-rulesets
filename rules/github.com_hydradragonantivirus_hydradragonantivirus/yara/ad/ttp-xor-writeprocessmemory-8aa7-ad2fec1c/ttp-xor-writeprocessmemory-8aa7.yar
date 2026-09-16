rule TTP_XOR_WriteProcessMemory_8aa7 {
  strings:
    $key_8aa7 = { dd d5 [2] ef f7 [2] e9 c2 [2] c7 c2 [2] f8 de }

  condition:
    any of them
}