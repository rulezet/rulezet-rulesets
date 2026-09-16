rule TTP_XOR_WriteProcessMemory_84a3 {
  strings:
    $key_84a3 = { d3 d1 [2] e1 f3 [2] e7 c6 [2] c9 c6 [2] f6 da }

  condition:
    any of them
}