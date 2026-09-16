rule TTP_XOR_WriteProcessMemory_9218 {
  strings:
    $key_9218 = { c5 6a [2] f7 48 [2] f1 7d [2] df 7d [2] e0 61 }

  condition:
    any of them
}