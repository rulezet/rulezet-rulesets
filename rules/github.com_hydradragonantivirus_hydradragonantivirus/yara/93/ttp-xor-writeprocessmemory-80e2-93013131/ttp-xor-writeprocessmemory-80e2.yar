rule TTP_XOR_WriteProcessMemory_80e2 {
  strings:
    $key_80e2 = { d7 90 [2] e5 b2 [2] e3 87 [2] cd 87 [2] f2 9b }

  condition:
    any of them
}