rule TTP_XOR_WriteProcessMemory_8ae6 {
  strings:
    $key_8ae6 = { dd 94 [2] ef b6 [2] e9 83 [2] c7 83 [2] f8 9f }

  condition:
    any of them
}