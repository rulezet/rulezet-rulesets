rule TTP_XOR_WriteProcessMemory_9268 {
  strings:
    $key_9268 = { c5 1a [2] f7 38 [2] f1 0d [2] df 0d [2] e0 11 }

  condition:
    any of them
}