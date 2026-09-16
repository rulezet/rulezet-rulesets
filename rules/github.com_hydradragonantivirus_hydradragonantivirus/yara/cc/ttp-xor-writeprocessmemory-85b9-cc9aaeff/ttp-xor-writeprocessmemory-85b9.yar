rule TTP_XOR_WriteProcessMemory_85b9 {
  strings:
    $key_85b9 = { d2 cb [2] e0 e9 [2] e6 dc [2] c8 dc [2] f7 c0 }

  condition:
    any of them
}