rule TTP_XOR_WriteProcessMemory_81b4 {
  strings:
    $key_81b4 = { d6 c6 [2] e4 e4 [2] e2 d1 [2] cc d1 [2] f3 cd }

  condition:
    any of them
}