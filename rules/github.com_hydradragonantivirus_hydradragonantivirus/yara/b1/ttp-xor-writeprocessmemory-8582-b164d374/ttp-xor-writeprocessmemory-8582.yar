rule TTP_XOR_WriteProcessMemory_8582 {
  strings:
    $key_8582 = { d2 f0 [2] e0 d2 [2] e6 e7 [2] c8 e7 [2] f7 fb }

  condition:
    any of them
}