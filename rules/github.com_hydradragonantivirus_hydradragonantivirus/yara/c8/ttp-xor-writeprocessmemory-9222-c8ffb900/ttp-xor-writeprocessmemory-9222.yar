rule TTP_XOR_WriteProcessMemory_9222 {
  strings:
    $key_9222 = { c5 50 [2] f7 72 [2] f1 47 [2] df 47 [2] e0 5b }

  condition:
    any of them
}