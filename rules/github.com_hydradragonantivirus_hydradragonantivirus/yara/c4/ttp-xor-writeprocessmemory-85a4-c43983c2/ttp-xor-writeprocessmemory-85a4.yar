rule TTP_XOR_WriteProcessMemory_85a4 {
  strings:
    $key_85a4 = { d2 d6 [2] e0 f4 [2] e6 c1 [2] c8 c1 [2] f7 dd }

  condition:
    any of them
}