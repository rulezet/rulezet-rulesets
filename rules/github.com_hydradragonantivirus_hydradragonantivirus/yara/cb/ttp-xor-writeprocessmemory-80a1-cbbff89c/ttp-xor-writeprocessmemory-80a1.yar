rule TTP_XOR_WriteProcessMemory_80a1 {
  strings:
    $key_80a1 = { d7 d3 [2] e5 f1 [2] e3 c4 [2] cd c4 [2] f2 d8 }

  condition:
    any of them
}