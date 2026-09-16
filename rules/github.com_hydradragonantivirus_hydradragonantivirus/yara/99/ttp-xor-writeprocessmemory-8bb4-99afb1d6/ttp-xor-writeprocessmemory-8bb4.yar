rule TTP_XOR_WriteProcessMemory_8bb4 {
  strings:
    $key_8bb4 = { dc c6 [2] ee e4 [2] e8 d1 [2] c6 d1 [2] f9 cd }

  condition:
    any of them
}