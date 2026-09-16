rule TTP_XOR_WriteProcessMemory_84d4 {
  strings:
    $key_84d4 = { d3 a6 [2] e1 84 [2] e7 b1 [2] c9 b1 [2] f6 ad }

  condition:
    any of them
}