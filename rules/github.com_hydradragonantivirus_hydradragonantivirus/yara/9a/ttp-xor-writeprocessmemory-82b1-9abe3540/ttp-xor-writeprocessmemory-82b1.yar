rule TTP_XOR_WriteProcessMemory_82b1 {
  strings:
    $key_82b1 = { d5 c3 [2] e7 e1 [2] e1 d4 [2] cf d4 [2] f0 c8 }

  condition:
    any of them
}