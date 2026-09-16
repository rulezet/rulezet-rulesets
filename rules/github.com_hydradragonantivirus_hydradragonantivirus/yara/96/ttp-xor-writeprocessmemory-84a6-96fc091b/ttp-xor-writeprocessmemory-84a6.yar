rule TTP_XOR_WriteProcessMemory_84a6 {
  strings:
    $key_84a6 = { d3 d4 [2] e1 f6 [2] e7 c3 [2] c9 c3 [2] f6 df }

  condition:
    any of them
}