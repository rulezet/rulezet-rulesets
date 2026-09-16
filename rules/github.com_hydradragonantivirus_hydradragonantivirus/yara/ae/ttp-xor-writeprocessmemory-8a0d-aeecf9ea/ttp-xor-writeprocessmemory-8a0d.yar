rule TTP_XOR_WriteProcessMemory_8a0d {
  strings:
    $key_8a0d = { dd 7f [2] ef 5d [2] e9 68 [2] c7 68 [2] f8 74 }

  condition:
    any of them
}