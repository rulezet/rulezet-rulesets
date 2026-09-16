rule TTP_XOR_WriteProcessMemory_8a48 {
  strings:
    $key_8a48 = { dd 3a [2] ef 18 [2] e9 2d [2] c7 2d [2] f8 31 }

  condition:
    any of them
}