rule TTP_XOR_WriteProcessMemory_80d1 {
  strings:
    $key_80d1 = { d7 a3 [2] e5 81 [2] e3 b4 [2] cd b4 [2] f2 a8 }

  condition:
    any of them
}