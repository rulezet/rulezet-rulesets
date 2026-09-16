rule TTP_XOR_WriteProcessMemory_8a81 {
  strings:
    $key_8a81 = { dd f3 [2] ef d1 [2] e9 e4 [2] c7 e4 [2] f8 f8 }

  condition:
    any of them
}