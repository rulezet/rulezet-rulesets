rule TTP_XOR_WriteProcessMemory_81b0 {
  strings:
    $key_81b0 = { d6 c2 [2] e4 e0 [2] e2 d5 [2] cc d5 [2] f3 c9 }

  condition:
    any of them
}