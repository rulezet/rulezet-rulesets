rule TTP_XOR_WriteProcessMemory_8af0 {
  strings:
    $key_8af0 = { dd 82 [2] ef a0 [2] e9 95 [2] c7 95 [2] f8 89 }

  condition:
    any of them
}