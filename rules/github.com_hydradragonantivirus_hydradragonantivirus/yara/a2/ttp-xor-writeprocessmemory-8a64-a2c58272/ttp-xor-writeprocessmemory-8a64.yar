rule TTP_XOR_WriteProcessMemory_8a64 {
  strings:
    $key_8a64 = { dd 16 [2] ef 34 [2] e9 01 [2] c7 01 [2] f8 1d }

  condition:
    any of them
}