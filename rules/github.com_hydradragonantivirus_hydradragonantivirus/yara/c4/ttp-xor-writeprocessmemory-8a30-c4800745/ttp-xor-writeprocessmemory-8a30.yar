rule TTP_XOR_WriteProcessMemory_8a30 {
  strings:
    $key_8a30 = { dd 42 [2] ef 60 [2] e9 55 [2] c7 55 [2] f8 49 }

  condition:
    any of them
}