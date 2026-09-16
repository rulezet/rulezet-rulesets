rule TTP_XOR_WriteProcessMemory_8bb5 {
  strings:
    $key_8bb5 = { dc c7 [2] ee e5 [2] e8 d0 [2] c6 d0 [2] f9 cc }

  condition:
    any of them
}