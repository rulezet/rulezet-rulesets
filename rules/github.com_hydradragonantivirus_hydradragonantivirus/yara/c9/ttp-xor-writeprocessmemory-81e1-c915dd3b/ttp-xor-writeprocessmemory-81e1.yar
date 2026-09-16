rule TTP_XOR_WriteProcessMemory_81e1 {
  strings:
    $key_81e1 = { d6 93 [2] e4 b1 [2] e2 84 [2] cc 84 [2] f3 98 }

  condition:
    any of them
}