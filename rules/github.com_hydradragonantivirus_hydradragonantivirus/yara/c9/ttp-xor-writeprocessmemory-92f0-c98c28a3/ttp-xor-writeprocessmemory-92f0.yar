rule TTP_XOR_WriteProcessMemory_92f0 {
  strings:
    $key_92f0 = { c5 82 [2] f7 a0 [2] f1 95 [2] df 95 [2] e0 89 }

  condition:
    any of them
}