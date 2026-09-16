rule TTP_XOR_WriteProcessMemory_92e7 {
  strings:
    $key_92e7 = { c5 95 [2] f7 b7 [2] f1 82 [2] df 82 [2] e0 9e }

  condition:
    any of them
}