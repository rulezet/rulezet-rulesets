rule TTP_XOR_WriteProcessMemory_81b3 {
  strings:
    $key_81b3 = { d6 c1 [2] e4 e3 [2] e2 d6 [2] cc d6 [2] f3 ca }

  condition:
    any of them
}