rule TTP_XOR_WriteProcessMemory_8a33 {
  strings:
    $key_8a33 = { dd 41 [2] ef 63 [2] e9 56 [2] c7 56 [2] f8 4a }

  condition:
    any of them
}