rule TTP_XOR_WriteProcessMemory_8ae3 {
  strings:
    $key_8ae3 = { dd 91 [2] ef b3 [2] e9 86 [2] c7 86 [2] f8 9a }

  condition:
    any of them
}