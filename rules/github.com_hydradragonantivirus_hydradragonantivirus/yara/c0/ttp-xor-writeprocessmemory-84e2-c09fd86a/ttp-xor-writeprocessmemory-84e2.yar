rule TTP_XOR_WriteProcessMemory_84e2 {
  strings:
    $key_84e2 = { d3 90 [2] e1 b2 [2] e7 87 [2] c9 87 [2] f6 9b }

  condition:
    any of them
}