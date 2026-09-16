rule TTP_XOR_WriteProcessMemory_9250 {
  strings:
    $key_9250 = { c5 22 [2] f7 00 [2] f1 35 [2] df 35 [2] e0 29 }

  condition:
    any of them
}