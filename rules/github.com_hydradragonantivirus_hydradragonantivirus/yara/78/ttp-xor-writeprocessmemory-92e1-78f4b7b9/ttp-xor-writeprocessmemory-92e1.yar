rule TTP_XOR_WriteProcessMemory_92e1 {
  strings:
    $key_92e1 = { c5 93 [2] f7 b1 [2] f1 84 [2] df 84 [2] e0 98 }

  condition:
    any of them
}