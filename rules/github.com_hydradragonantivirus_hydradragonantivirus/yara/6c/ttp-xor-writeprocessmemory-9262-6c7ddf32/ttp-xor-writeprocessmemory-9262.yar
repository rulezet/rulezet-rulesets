rule TTP_XOR_WriteProcessMemory_9262 {
  strings:
    $key_9262 = { c5 10 [2] f7 32 [2] f1 07 [2] df 07 [2] e0 1b }

  condition:
    any of them
}