rule TTP_XOR_WriteProcessMemory_9221 {
  strings:
    $key_9221 = { c5 53 [2] f7 71 [2] f1 44 [2] df 44 [2] e0 58 }

  condition:
    any of them
}