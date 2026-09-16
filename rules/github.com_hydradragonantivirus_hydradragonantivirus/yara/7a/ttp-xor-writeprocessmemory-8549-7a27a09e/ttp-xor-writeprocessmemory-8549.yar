rule TTP_XOR_WriteProcessMemory_8549 {
  strings:
    $key_8549 = { d2 3b [2] e0 19 [2] e6 2c [2] c8 2c [2] f7 30 }

  condition:
    any of them
}