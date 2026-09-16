rule TTP_XOR_WriteProcessMemory_9251 {
  strings:
    $key_9251 = { c5 23 [2] f7 01 [2] f1 34 [2] df 34 [2] e0 28 }

  condition:
    any of them
}