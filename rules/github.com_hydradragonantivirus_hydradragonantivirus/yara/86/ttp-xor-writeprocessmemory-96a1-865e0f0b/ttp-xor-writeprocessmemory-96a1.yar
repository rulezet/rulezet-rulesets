rule TTP_XOR_WriteProcessMemory_96a1 {
  strings:
    $key_96a1 = { c1 d3 [2] f3 f1 [2] f5 c4 [2] db c4 [2] e4 d8 }

  condition:
    any of them
}