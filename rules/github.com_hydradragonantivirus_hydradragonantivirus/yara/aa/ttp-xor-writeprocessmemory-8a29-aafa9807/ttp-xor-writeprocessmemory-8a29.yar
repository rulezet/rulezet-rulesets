rule TTP_XOR_WriteProcessMemory_8a29 {
  strings:
    $key_8a29 = { dd 5b [2] ef 79 [2] e9 4c [2] c7 4c [2] f8 50 }

  condition:
    any of them
}