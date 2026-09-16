rule TTP_XOR_WriteProcessMemory_80e0 {
  strings:
    $key_80e0 = { d7 92 [2] e5 b0 [2] e3 85 [2] cd 85 [2] f2 99 }

  condition:
    any of them
}