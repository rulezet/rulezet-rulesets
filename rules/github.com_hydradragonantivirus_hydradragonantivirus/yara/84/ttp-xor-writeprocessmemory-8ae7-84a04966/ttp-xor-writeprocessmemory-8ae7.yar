rule TTP_XOR_WriteProcessMemory_8ae7 {
  strings:
    $key_8ae7 = { dd 95 [2] ef b7 [2] e9 82 [2] c7 82 [2] f8 9e }

  condition:
    any of them
}