rule TTP_XOR_WriteProcessMemory_8a3d {
  strings:
    $key_8a3d = { dd 4f [2] ef 6d [2] e9 58 [2] c7 58 [2] f8 44 }

  condition:
    any of them
}