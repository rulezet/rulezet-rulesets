rule TTP_XOR_WriteProcessMemory_81e7 {
  strings:
    $key_81e7 = { d6 95 [2] e4 b7 [2] e2 82 [2] cc 82 [2] f3 9e }

  condition:
    any of them
}