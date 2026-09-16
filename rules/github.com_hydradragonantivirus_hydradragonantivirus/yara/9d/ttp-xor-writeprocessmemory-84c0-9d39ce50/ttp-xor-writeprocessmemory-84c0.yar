rule TTP_XOR_WriteProcessMemory_84c0 {
  strings:
    $key_84c0 = { d3 b2 [2] e1 90 [2] e7 a5 [2] c9 a5 [2] f6 b9 }

  condition:
    any of them
}