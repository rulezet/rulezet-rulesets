rule TTP_XOR_WriteProcessMemory_9272 {
  strings:
    $key_9272 = { c5 00 [2] f7 22 [2] f1 17 [2] df 17 [2] e0 0b }

  condition:
    any of them
}