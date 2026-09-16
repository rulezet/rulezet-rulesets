rule TTP_XOR_WriteProcessMemory_9680 {
  strings:
    $key_9680 = { c1 f2 [2] f3 d0 [2] f5 e5 [2] db e5 [2] e4 f9 }

  condition:
    any of them
}