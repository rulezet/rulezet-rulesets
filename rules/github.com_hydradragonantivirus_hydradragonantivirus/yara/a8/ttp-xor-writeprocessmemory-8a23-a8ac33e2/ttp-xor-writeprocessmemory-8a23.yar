rule TTP_XOR_WriteProcessMemory_8a23 {
  strings:
    $key_8a23 = { dd 51 [2] ef 73 [2] e9 46 [2] c7 46 [2] f8 5a }

  condition:
    any of them
}