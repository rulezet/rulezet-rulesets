rule TTP_XOR_WriteProcessMemory_9213 {
  strings:
    $key_9213 = { c5 61 [2] f7 43 [2] f1 76 [2] df 76 [2] e0 6a }

  condition:
    any of them
}