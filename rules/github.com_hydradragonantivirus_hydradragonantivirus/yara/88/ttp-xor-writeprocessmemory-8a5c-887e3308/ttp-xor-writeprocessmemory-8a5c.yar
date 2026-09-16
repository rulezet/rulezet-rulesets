rule TTP_XOR_WriteProcessMemory_8a5c {
  strings:
    $key_8a5c = { dd 2e [2] ef 0c [2] e9 39 [2] c7 39 [2] f8 25 }

  condition:
    any of them
}