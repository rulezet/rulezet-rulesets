rule TTP_XOR_WriteProcessMemory_8bb0 {
  strings:
    $key_8bb0 = { dc c2 [2] ee e0 [2] e8 d5 [2] c6 d5 [2] f9 c9 }

  condition:
    any of them
}