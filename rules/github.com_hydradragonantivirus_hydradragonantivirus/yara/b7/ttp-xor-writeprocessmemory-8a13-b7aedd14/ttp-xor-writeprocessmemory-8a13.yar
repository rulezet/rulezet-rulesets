rule TTP_XOR_WriteProcessMemory_8a13 {
  strings:
    $key_8a13 = { dd 61 [2] ef 43 [2] e9 76 [2] c7 76 [2] f8 6a }

  condition:
    any of them
}