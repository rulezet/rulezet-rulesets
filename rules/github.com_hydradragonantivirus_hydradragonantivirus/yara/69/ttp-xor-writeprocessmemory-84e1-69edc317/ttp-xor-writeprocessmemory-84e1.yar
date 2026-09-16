rule TTP_XOR_WriteProcessMemory_84e1 {
  strings:
    $key_84e1 = { d3 93 [2] e1 b1 [2] e7 84 [2] c9 84 [2] f6 98 }

  condition:
    any of them
}