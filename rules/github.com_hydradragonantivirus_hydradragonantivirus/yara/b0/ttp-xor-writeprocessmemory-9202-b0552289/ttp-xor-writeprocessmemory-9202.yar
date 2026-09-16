rule TTP_XOR_WriteProcessMemory_9202 {
  strings:
    $key_9202 = { c5 70 [2] f7 52 [2] f1 67 [2] df 67 [2] e0 7b }

  condition:
    any of them
}