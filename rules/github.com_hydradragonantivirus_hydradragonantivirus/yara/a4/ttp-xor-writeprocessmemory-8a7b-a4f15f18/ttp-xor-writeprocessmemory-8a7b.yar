rule TTP_XOR_WriteProcessMemory_8a7b {
  strings:
    $key_8a7b = { dd 09 [2] ef 2b [2] e9 1e [2] c7 1e [2] f8 02 }

  condition:
    any of them
}