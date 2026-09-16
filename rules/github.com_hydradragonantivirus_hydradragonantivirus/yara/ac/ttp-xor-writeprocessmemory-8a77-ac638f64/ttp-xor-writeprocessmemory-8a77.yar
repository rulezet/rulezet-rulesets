rule TTP_XOR_WriteProcessMemory_8a77 {
  strings:
    $key_8a77 = { dd 05 [2] ef 27 [2] e9 12 [2] c7 12 [2] f8 0e }

  condition:
    any of them
}