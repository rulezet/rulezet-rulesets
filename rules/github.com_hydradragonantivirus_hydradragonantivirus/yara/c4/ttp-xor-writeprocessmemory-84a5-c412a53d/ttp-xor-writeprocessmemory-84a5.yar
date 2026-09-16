rule TTP_XOR_WriteProcessMemory_84a5 {
  strings:
    $key_84a5 = { d3 d7 [2] e1 f5 [2] e7 c0 [2] c9 c0 [2] f6 dc }

  condition:
    any of them
}