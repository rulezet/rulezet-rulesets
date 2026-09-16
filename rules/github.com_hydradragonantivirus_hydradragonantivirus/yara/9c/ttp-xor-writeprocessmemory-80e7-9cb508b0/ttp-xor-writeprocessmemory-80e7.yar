rule TTP_XOR_WriteProcessMemory_80e7 {
  strings:
    $key_80e7 = { d7 95 [2] e5 b7 [2] e3 82 [2] cd 82 [2] f2 9e }

  condition:
    any of them
}