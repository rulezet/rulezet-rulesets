rule TTP_XOR_WriteProcessMemory_8a60 {
  strings:
    $key_8a60 = { dd 12 [2] ef 30 [2] e9 05 [2] c7 05 [2] f8 19 }

  condition:
    any of them
}