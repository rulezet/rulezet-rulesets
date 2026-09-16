rule TTP_XOR_WriteProcessMemory_8a5e {
  strings:
    $key_8a5e = { dd 2c [2] ef 0e [2] e9 3b [2] c7 3b [2] f8 27 }

  condition:
    any of them
}