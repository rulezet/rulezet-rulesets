rule TTP_XOR_WriteProcessMemory_8bb1 {
  strings:
    $key_8bb1 = { dc c3 [2] ee e1 [2] e8 d4 [2] c6 d4 [2] f9 c8 }

  condition:
    any of them
}