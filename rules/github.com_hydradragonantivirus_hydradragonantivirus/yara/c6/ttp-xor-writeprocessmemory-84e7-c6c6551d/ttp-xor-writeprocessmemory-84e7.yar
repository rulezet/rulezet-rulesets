rule TTP_XOR_WriteProcessMemory_84e7 {
  strings:
    $key_84e7 = { d3 95 [2] e1 b7 [2] e7 82 [2] c9 82 [2] f6 9e }

  condition:
    any of them
}