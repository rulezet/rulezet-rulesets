rule TTP_XOR_WriteProcessMemory_8aa5 {
  strings:
    $key_8aa5 = { dd d7 [2] ef f5 [2] e9 c0 [2] c7 c0 [2] f8 dc }

  condition:
    any of them
}