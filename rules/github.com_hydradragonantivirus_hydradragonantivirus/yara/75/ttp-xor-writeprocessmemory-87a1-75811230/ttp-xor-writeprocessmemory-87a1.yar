rule TTP_XOR_WriteProcessMemory_87a1 {
  strings:
    $key_87a1 = { d0 d3 [2] e2 f1 [2] e4 c4 [2] ca c4 [2] f5 d8 }

  condition:
    any of them
}