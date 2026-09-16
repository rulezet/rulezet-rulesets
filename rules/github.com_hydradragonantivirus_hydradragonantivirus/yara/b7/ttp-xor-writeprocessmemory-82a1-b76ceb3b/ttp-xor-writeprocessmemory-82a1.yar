rule TTP_XOR_WriteProcessMemory_82a1 {
  strings:
    $key_82a1 = { d5 d3 [2] e7 f1 [2] e1 c4 [2] cf c4 [2] f0 d8 }

  condition:
    any of them
}