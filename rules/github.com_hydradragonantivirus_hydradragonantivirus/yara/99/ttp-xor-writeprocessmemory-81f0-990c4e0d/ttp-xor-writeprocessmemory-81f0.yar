rule TTP_XOR_WriteProcessMemory_81f0 {
  strings:
    $key_81f0 = { d6 82 [2] e4 a0 [2] e2 95 [2] cc 95 [2] f3 89 }

  condition:
    any of them
}