rule TTP_XOR_WriteProcessMemory_8a04 {
  strings:
    $key_8a04 = { dd 76 [2] ef 54 [2] e9 61 [2] c7 61 [2] f8 7d }

  condition:
    any of them
}