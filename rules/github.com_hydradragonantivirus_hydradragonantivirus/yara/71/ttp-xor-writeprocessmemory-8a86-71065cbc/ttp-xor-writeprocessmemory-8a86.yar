rule TTP_XOR_WriteProcessMemory_8a86 {
  strings:
    $key_8a86 = { dd f4 [2] ef d6 [2] e9 e3 [2] c7 e3 [2] f8 ff }

  condition:
    any of them
}