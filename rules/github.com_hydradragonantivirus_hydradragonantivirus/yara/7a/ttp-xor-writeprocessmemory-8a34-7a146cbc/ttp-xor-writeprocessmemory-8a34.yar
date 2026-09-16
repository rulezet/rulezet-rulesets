rule TTP_XOR_WriteProcessMemory_8a34 {
  strings:
    $key_8a34 = { dd 46 [2] ef 64 [2] e9 51 [2] c7 51 [2] f8 4d }

  condition:
    any of them
}