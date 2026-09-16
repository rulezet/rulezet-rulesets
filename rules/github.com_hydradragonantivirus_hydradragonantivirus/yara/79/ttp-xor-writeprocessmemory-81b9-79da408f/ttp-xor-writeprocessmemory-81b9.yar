rule TTP_XOR_WriteProcessMemory_81b9 {
  strings:
    $key_81b9 = { d6 cb [2] e4 e9 [2] e2 dc [2] cc dc [2] f3 c0 }

  condition:
    any of them
}