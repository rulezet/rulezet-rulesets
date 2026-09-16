rule TTP_XOR_WriteProcessMemory_8a53 {
  strings:
    $key_8a53 = { dd 21 [2] ef 03 [2] e9 36 [2] c7 36 [2] f8 2a }

  condition:
    any of them
}