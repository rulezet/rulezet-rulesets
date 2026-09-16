rule TTP_XOR_WriteProcessMemory_80a0 {
  strings:
    $key_80a0 = { d7 d2 [2] e5 f0 [2] e3 c5 [2] cd c5 [2] f2 d9 }

  condition:
    any of them
}