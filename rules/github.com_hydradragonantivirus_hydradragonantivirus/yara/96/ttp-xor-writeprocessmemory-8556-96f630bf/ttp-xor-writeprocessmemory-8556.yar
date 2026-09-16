rule TTP_XOR_WriteProcessMemory_8556 {
  strings:
    $key_8556 = { d2 24 [2] e0 06 [2] e6 33 [2] c8 33 [2] f7 2f }

  condition:
    any of them
}