rule TTP_XOR_WriteProcessMemory_81a0 {
  strings:
    $key_81a0 = { d6 d2 [2] e4 f0 [2] e2 c5 [2] cc c5 [2] f3 d9 }

  condition:
    any of them
}