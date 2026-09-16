rule TTP_XOR_WriteProcessMemory_8a49 {
  strings:
    $key_8a49 = { dd 3b [2] ef 19 [2] e9 2c [2] c7 2c [2] f8 30 }

  condition:
    any of them
}