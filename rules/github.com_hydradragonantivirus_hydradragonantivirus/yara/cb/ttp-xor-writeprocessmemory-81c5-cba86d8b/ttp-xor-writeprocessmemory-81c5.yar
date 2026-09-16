rule TTP_XOR_WriteProcessMemory_81c5 {
  strings:
    $key_81c5 = { d6 b7 [2] e4 95 [2] e2 a0 [2] cc a0 [2] f3 bc }

  condition:
    any of them
}