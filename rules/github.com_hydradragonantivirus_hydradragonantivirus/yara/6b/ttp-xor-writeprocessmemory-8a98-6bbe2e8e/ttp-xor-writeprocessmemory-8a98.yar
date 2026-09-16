rule TTP_XOR_WriteProcessMemory_8a98 {
  strings:
    $key_8a98 = { dd ea [2] ef c8 [2] e9 fd [2] c7 fd [2] f8 e1 }

  condition:
    any of them
}