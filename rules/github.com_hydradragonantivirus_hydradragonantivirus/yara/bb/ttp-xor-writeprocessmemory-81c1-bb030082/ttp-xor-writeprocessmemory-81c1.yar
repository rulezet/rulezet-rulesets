rule TTP_XOR_WriteProcessMemory_81c1 {
  strings:
    $key_81c1 = { d6 b3 [2] e4 91 [2] e2 a4 [2] cc a4 [2] f3 b8 }

  condition:
    any of them
}