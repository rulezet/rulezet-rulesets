rule TTP_XOR_WriteProcessMemory_8aa1 {
  strings:
    $key_8aa1 = { dd d3 [2] ef f1 [2] e9 c4 [2] c7 c4 [2] f8 d8 }

  condition:
    any of them
}