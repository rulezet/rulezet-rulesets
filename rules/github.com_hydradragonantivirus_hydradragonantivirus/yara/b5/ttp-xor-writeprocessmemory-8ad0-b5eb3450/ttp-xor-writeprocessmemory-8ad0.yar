rule TTP_XOR_WriteProcessMemory_8ad0 {
  strings:
    $key_8ad0 = { dd a2 [2] ef 80 [2] e9 b5 [2] c7 b5 [2] f8 a9 }

  condition:
    any of them
}