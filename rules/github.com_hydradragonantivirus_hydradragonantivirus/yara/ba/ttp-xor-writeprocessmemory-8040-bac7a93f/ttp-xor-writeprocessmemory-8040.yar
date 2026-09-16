rule TTP_XOR_WriteProcessMemory_8040 {
  strings:
    $key_8040 = { d7 32 [2] e5 10 [2] e3 25 [2] cd 25 [2] f2 39 }

  condition:
    any of them
}