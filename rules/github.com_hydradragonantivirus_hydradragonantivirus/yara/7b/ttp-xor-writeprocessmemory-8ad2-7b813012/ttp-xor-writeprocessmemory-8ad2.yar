rule TTP_XOR_WriteProcessMemory_8ad2 {
  strings:
    $key_8ad2 = { dd a0 [2] ef 82 [2] e9 b7 [2] c7 b7 [2] f8 ab }

  condition:
    any of them
}