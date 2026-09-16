rule TTP_XOR_WriteProcessMemory_8a72 {
  strings:
    $key_8a72 = { dd 00 [2] ef 22 [2] e9 17 [2] c7 17 [2] f8 0b }

  condition:
    any of them
}