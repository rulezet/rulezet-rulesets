rule TTP_XOR_WriteProcessMemory_85a3 {
  strings:
    $key_85a3 = { d2 d1 [2] e0 f3 [2] e6 c6 [2] c8 c6 [2] f7 da }

  condition:
    any of them
}