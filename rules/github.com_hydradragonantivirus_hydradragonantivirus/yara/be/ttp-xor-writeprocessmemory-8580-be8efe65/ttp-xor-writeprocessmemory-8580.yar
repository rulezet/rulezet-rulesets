rule TTP_XOR_WriteProcessMemory_8580 {
  strings:
    $key_8580 = { d2 f2 [2] e0 d0 [2] e6 e5 [2] c8 e5 [2] f7 f9 }

  condition:
    any of them
}