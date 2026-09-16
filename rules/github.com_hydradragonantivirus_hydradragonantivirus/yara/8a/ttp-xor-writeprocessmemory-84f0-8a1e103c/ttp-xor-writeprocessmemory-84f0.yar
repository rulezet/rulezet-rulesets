rule TTP_XOR_WriteProcessMemory_84f0 {
  strings:
    $key_84f0 = { d3 82 [2] e1 a0 [2] e7 95 [2] c9 95 [2] f6 89 }

  condition:
    any of them
}