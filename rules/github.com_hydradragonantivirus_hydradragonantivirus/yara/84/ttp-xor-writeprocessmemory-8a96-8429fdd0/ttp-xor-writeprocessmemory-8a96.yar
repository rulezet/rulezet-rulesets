rule TTP_XOR_WriteProcessMemory_8a96 {
  strings:
    $key_8a96 = { dd e4 [2] ef c6 [2] e9 f3 [2] c7 f3 [2] f8 ef }

  condition:
    any of them
}