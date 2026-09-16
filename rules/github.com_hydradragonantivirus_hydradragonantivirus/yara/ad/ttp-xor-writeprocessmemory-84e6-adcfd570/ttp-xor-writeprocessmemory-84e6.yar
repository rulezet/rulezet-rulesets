rule TTP_XOR_WriteProcessMemory_84e6 {
  strings:
    $key_84e6 = { d3 94 [2] e1 b6 [2] e7 83 [2] c9 83 [2] f6 9f }

  condition:
    any of them
}