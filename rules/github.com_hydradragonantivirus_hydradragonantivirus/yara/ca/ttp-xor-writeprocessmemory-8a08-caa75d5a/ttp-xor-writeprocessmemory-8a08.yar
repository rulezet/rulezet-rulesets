rule TTP_XOR_WriteProcessMemory_8a08 {
  strings:
    $key_8a08 = { dd 7a [2] ef 58 [2] e9 6d [2] c7 6d [2] f8 71 }

  condition:
    any of them
}