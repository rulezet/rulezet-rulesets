rule TTP_XOR_WriteProcessMemory_84e0 {
  strings:
    $key_84e0 = { d3 92 [2] e1 b0 [2] e7 85 [2] c9 85 [2] f6 99 }

  condition:
    any of them
}