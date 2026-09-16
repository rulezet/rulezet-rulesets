rule TTP_XOR_WriteProcessMemory_8a7c {
  strings:
    $key_8a7c = { dd 0e [2] ef 2c [2] e9 19 [2] c7 19 [2] f8 05 }

  condition:
    any of them
}