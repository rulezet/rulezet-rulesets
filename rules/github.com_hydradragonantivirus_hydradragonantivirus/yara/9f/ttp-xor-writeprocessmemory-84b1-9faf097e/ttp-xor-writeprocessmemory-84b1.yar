rule TTP_XOR_WriteProcessMemory_84b1 {
  strings:
    $key_84b1 = { d3 c3 [2] e1 e1 [2] e7 d4 [2] c9 d4 [2] f6 c8 }

  condition:
    any of them
}