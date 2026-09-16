rule TTP_XOR_WriteProcessMemory_9208 {
  strings:
    $key_9208 = { c5 7a [2] f7 58 [2] f1 6d [2] df 6d [2] e0 71 }

  condition:
    any of them
}