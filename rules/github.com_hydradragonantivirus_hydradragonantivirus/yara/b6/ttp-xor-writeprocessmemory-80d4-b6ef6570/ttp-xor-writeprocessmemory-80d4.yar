rule TTP_XOR_WriteProcessMemory_80d4 {
  strings:
    $key_80d4 = { d7 a6 [2] e5 84 [2] e3 b1 [2] cd b1 [2] f2 ad }

  condition:
    any of them
}