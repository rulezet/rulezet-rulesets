rule TTP_XOR_WriteProcessMemory_8a1d {
  strings:
    $key_8a1d = { dd 6f [2] ef 4d [2] e9 78 [2] c7 78 [2] f8 64 }

  condition:
    any of them
}