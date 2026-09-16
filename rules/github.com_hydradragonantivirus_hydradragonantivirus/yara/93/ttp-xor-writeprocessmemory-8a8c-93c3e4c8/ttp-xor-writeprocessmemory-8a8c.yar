rule TTP_XOR_WriteProcessMemory_8a8c {
  strings:
    $key_8a8c = { dd fe [2] ef dc [2] e9 e9 [2] c7 e9 [2] f8 f5 }

  condition:
    any of them
}