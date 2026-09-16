rule TTP_XOR_WriteProcessMemory_8a71 {
  strings:
    $key_8a71 = { dd 03 [2] ef 21 [2] e9 14 [2] c7 14 [2] f8 08 }

  condition:
    any of them
}