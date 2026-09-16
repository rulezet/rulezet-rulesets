rule TTP_XOR_WriteProcessMemory_8a47 {
  strings:
    $key_8a47 = { dd 35 [2] ef 17 [2] e9 22 [2] c7 22 [2] f8 3e }

  condition:
    any of them
}