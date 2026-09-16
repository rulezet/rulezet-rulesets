rule TTP_XOR_WriteProcessMemory_8a21 {
  strings:
    $key_8a21 = { dd 53 [2] ef 71 [2] e9 44 [2] c7 44 [2] f8 58 }

  condition:
    any of them
}