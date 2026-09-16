rule TTP_XOR_WriteProcessMemory_81d1 {
  strings:
    $key_81d1 = { d6 a3 [2] e4 81 [2] e2 b4 [2] cc b4 [2] f3 a8 }

  condition:
    any of them
}