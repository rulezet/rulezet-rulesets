rule TTP_XOR_WriteProcessMemory_81e6 {
  strings:
    $key_81e6 = { d6 94 [2] e4 b6 [2] e2 83 [2] cc 83 [2] f3 9f }

  condition:
    any of them
}