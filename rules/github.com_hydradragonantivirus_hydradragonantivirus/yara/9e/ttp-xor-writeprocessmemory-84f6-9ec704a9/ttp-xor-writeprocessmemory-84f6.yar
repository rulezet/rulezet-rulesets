rule TTP_XOR_WriteProcessMemory_84f6 {
  strings:
    $key_84f6 = { d3 84 [2] e1 a6 [2] e7 93 [2] c9 93 [2] f6 8f }

  condition:
    any of them
}