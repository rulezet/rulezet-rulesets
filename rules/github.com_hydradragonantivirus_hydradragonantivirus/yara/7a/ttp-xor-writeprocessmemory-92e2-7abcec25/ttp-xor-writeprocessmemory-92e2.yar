rule TTP_XOR_WriteProcessMemory_92e2 {
  strings:
    $key_92e2 = { c5 90 [2] f7 b2 [2] f1 87 [2] df 87 [2] e0 9b }

  condition:
    any of them
}