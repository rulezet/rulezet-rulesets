rule TTP_XOR_WriteProcessMemory_8bb9 {
  strings:
    $key_8bb9 = { dc cb [2] ee e9 [2] e8 dc [2] c6 dc [2] f9 c0 }

  condition:
    any of them
}