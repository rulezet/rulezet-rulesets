rule TTP_XOR_WriteProcessMemory_8a55 {
  strings:
    $key_8a55 = { dd 27 [2] ef 05 [2] e9 30 [2] c7 30 [2] f8 2c }

  condition:
    any of them
}