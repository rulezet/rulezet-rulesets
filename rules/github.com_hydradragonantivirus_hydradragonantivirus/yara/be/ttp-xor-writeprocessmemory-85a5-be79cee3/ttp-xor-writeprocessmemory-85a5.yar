rule TTP_XOR_WriteProcessMemory_85a5 {
  strings:
    $key_85a5 = { d2 d7 [2] e0 f5 [2] e6 c0 [2] c8 c0 [2] f7 dc }

  condition:
    any of them
}