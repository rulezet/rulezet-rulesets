rule TTP_XOR_WriteProcessMemory_8af1 {
  strings:
    $key_8af1 = { dd 83 [2] ef a1 [2] e9 94 [2] c7 94 [2] f8 88 }

  condition:
    any of them
}