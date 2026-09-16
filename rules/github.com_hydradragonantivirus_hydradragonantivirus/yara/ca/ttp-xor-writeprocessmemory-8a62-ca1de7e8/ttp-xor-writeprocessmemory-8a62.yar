rule TTP_XOR_WriteProcessMemory_8a62 {
  strings:
    $key_8a62 = { dd 10 [2] ef 32 [2] e9 07 [2] c7 07 [2] f8 1b }

  condition:
    any of them
}