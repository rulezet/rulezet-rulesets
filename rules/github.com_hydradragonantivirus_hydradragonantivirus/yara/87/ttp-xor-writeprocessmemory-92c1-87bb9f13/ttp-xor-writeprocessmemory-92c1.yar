rule TTP_XOR_WriteProcessMemory_92c1 {
  strings:
    $key_92c1 = { c5 b3 [2] f7 91 [2] f1 a4 [2] df a4 [2] e0 b8 }

  condition:
    any of them
}