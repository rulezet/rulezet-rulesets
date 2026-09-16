rule TTP_XOR_WriteProcessMemory_9681 {
  strings:
    $key_9681 = { c1 f3 [2] f3 d1 [2] f5 e4 [2] db e4 [2] e4 f8 }

  condition:
    any of them
}