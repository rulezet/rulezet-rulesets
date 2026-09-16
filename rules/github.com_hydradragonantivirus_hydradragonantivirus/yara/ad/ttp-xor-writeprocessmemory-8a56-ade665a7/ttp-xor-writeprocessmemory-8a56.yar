rule TTP_XOR_WriteProcessMemory_8a56 {
  strings:
    $key_8a56 = { dd 24 [2] ef 06 [2] e9 33 [2] c7 33 [2] f8 2f }

  condition:
    any of them
}