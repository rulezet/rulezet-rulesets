rule TTP_XOR_WriteProcessMemory_97a1 {
  strings:
    $key_97a1 = { c0 d3 [2] f2 f1 [2] f4 c4 [2] da c4 [2] e5 d8 }

  condition:
    any of them
}