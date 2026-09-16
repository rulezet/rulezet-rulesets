rule TTP_XOR_WriteProcessMemory_81d4 {
  strings:
    $key_81d4 = { d6 a6 [2] e4 84 [2] e2 b1 [2] cc b1 [2] f3 ad }

  condition:
    any of them
}