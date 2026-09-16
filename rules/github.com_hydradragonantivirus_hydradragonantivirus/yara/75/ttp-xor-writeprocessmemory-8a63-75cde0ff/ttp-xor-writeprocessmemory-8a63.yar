rule TTP_XOR_WriteProcessMemory_8a63 {
  strings:
    $key_8a63 = { dd 11 [2] ef 33 [2] e9 06 [2] c7 06 [2] f8 1a }

  condition:
    any of them
}