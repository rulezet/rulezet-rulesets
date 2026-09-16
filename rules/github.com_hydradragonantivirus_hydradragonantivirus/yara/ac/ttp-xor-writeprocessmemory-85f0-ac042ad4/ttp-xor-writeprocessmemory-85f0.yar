rule TTP_XOR_WriteProcessMemory_85f0 {
  strings:
    $key_85f0 = { d2 82 [2] e0 a0 [2] e6 95 [2] c8 95 [2] f7 89 }

  condition:
    any of them
}