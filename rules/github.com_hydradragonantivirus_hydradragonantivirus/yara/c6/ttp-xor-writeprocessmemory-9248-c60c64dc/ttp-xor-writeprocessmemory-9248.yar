rule TTP_XOR_WriteProcessMemory_9248 {
  strings:
    $key_9248 = { c5 3a [2] f7 18 [2] f1 2d [2] df 2d [2] e0 31 }

  condition:
    any of them
}