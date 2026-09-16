rule TTP_XOR_WriteProcessMemory_8ae2 {
  strings:
    $key_8ae2 = { dd 90 [2] ef b2 [2] e9 87 [2] c7 87 [2] f8 9b }

  condition:
    any of them
}