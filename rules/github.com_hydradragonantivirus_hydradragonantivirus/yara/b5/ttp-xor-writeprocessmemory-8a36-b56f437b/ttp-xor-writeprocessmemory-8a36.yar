rule TTP_XOR_WriteProcessMemory_8a36 {
  strings:
    $key_8a36 = { dd 44 [2] ef 66 [2] e9 53 [2] c7 53 [2] f8 4f }

  condition:
    any of them
}