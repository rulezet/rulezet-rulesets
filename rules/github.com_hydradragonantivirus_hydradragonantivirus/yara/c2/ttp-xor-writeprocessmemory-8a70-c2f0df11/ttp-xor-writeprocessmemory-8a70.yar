rule TTP_XOR_WriteProcessMemory_8a70 {
  strings:
    $key_8a70 = { dd 02 [2] ef 20 [2] e9 15 [2] c7 15 [2] f8 09 }

  condition:
    any of them
}