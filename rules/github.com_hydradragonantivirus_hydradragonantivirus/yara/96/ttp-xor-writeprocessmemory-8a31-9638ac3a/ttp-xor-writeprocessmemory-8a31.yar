rule TTP_XOR_WriteProcessMemory_8a31 {
  strings:
    $key_8a31 = { dd 43 [2] ef 61 [2] e9 54 [2] c7 54 [2] f8 48 }

  condition:
    any of them
}