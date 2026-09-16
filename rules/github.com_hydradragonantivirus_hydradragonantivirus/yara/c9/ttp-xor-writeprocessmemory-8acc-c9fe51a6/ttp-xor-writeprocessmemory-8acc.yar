rule TTP_XOR_WriteProcessMemory_8acc {
  strings:
    $key_8acc = { dd be [2] ef 9c [2] e9 a9 [2] c7 a9 [2] f8 b5 }

  condition:
    any of them
}