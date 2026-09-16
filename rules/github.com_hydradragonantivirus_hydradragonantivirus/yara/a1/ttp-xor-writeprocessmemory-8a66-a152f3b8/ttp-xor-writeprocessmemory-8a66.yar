rule TTP_XOR_WriteProcessMemory_8a66 {
  strings:
    $key_8a66 = { dd 14 [2] ef 36 [2] e9 03 [2] c7 03 [2] f8 1f }

  condition:
    any of them
}