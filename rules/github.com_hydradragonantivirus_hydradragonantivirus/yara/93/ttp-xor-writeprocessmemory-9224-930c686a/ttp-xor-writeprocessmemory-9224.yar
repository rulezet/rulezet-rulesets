rule TTP_XOR_WriteProcessMemory_9224 {
  strings:
    $key_9224 = { c5 56 [2] f7 74 [2] f1 41 [2] df 41 [2] e0 5d }

  condition:
    any of them
}