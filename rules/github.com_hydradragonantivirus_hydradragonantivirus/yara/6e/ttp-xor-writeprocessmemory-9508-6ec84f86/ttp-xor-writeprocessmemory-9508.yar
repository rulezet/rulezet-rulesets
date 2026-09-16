rule TTP_XOR_WriteProcessMemory_9508 {
  strings:
    $key_9508 = { c2 7a [2] f0 58 [2] f6 6d [2] d8 6d [2] e7 71 }

  condition:
    any of them
}