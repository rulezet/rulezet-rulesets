rule TTP_XOR_WriteProcessMemory_8a1c {
  strings:
    $key_8a1c = { dd 6e [2] ef 4c [2] e9 79 [2] c7 79 [2] f8 65 }

  condition:
    any of them
}