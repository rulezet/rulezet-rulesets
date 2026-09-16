rule TTP_XOR_WriteProcessMemory_8a9c {
  strings:
    $key_8a9c = { dd ee [2] ef cc [2] e9 f9 [2] c7 f9 [2] f8 e5 }

  condition:
    any of them
}