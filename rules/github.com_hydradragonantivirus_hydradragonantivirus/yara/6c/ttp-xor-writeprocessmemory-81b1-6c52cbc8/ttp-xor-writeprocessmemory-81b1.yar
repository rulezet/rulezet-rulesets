rule TTP_XOR_WriteProcessMemory_81b1 {
  strings:
    $key_81b1 = { d6 c3 [2] e4 e1 [2] e2 d4 [2] cc d4 [2] f3 c8 }

  condition:
    any of them
}