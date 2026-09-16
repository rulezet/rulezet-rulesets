rule TTP_XOR_WriteProcessMemory_92a0 {
  strings:
    $key_92a0 = { c5 d2 [2] f7 f0 [2] f1 c5 [2] df c5 [2] e0 d9 }

  condition:
    any of them
}