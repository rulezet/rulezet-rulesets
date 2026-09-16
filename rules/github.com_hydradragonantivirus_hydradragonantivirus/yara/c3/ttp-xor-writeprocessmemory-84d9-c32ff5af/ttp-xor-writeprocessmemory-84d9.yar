rule TTP_XOR_WriteProcessMemory_84d9 {
  strings:
    $key_84d9 = { d3 ab [2] e1 89 [2] e7 bc [2] c9 bc [2] f6 a0 }

  condition:
    any of them
}