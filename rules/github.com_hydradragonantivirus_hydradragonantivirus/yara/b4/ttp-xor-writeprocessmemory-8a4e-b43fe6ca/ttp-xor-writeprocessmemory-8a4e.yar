rule TTP_XOR_WriteProcessMemory_8a4e {
  strings:
    $key_8a4e = { dd 3c [2] ef 1e [2] e9 2b [2] c7 2b [2] f8 37 }

  condition:
    any of them
}