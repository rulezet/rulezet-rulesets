rule TTP_XOR_WriteProcessMemory_8af2 {
  strings:
    $key_8af2 = { dd 80 [2] ef a2 [2] e9 97 [2] c7 97 [2] f8 8b }

  condition:
    any of them
}