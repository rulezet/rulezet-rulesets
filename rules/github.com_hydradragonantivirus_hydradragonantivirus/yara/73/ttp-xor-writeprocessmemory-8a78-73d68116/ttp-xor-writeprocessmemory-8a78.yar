rule TTP_XOR_WriteProcessMemory_8a78 {
  strings:
    $key_8a78 = { dd 0a [2] ef 28 [2] e9 1d [2] c7 1d [2] f8 01 }

  condition:
    any of them
}