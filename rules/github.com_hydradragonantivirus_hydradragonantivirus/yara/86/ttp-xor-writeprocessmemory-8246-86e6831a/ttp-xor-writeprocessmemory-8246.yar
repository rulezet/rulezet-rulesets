rule TTP_XOR_WriteProcessMemory_8246 {
  strings:
    $key_8246 = { d5 34 [2] e7 16 [2] e1 23 [2] cf 23 [2] f0 3f }

  condition:
    any of them
}