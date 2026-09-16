rule TTP_XOR_WriteProcessMemory_97b1 {
  strings:
    $key_97b1 = { c0 c3 [2] f2 e1 [2] f4 d4 [2] da d4 [2] e5 c8 }

  condition:
    any of them
}