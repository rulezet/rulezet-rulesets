rule TTP_XOR_WriteProcessMemory_8a51 {
  strings:
    $key_8a51 = { dd 23 [2] ef 01 [2] e9 34 [2] c7 34 [2] f8 28 }

  condition:
    any of them
}