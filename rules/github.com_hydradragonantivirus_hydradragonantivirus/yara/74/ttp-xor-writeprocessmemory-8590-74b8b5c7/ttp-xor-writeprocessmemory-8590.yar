rule TTP_XOR_WriteProcessMemory_8590 {
  strings:
    $key_8590 = { d2 e2 [2] e0 c0 [2] e6 f5 [2] c8 f5 [2] f7 e9 }

  condition:
    any of them
}