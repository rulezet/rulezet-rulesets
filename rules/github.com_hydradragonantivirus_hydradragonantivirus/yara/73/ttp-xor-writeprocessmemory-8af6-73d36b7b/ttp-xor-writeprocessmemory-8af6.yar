rule TTP_XOR_WriteProcessMemory_8af6 {
  strings:
    $key_8af6 = { dd 84 [2] ef a6 [2] e9 93 [2] c7 93 [2] f8 8f }

  condition:
    any of them
}