rule TTP_XOR_WriteProcessMemory_8046 {
  strings:
    $key_8046 = { d7 34 [2] e5 16 [2] e3 23 [2] cd 23 [2] f2 3f }

  condition:
    any of them
}