rule TTP_XOR_WriteProcessMemory_81c3 {
  strings:
    $key_81c3 = { d6 b1 [2] e4 93 [2] e2 a6 [2] cc a6 [2] f3 ba }

  condition:
    any of them
}