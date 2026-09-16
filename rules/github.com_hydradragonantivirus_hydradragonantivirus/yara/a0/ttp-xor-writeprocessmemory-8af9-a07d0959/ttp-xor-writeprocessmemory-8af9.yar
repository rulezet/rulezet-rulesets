rule TTP_XOR_WriteProcessMemory_8af9 {
  strings:
    $key_8af9 = { dd 8b [2] ef a9 [2] e9 9c [2] c7 9c [2] f8 80 }

  condition:
    any of them
}