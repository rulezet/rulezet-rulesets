rule TTP_XOR_WriteProcessMemory_9257 {
  strings:
    $key_9257 = { c5 25 [2] f7 07 [2] f1 32 [2] df 32 [2] e0 2e }

  condition:
    any of them
}