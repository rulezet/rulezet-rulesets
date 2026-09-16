rule TTP_XOR_WriteProcessMemory_8a17 {
  strings:
    $key_8a17 = { dd 65 [2] ef 47 [2] e9 72 [2] c7 72 [2] f8 6e }

  condition:
    any of them
}