rule TTP_XOR_WriteProcessMemory_8146 {
  strings:
    $key_8146 = { d6 34 [2] e4 16 [2] e2 23 [2] cc 23 [2] f3 3f }

  condition:
    any of them
}