rule TTP_XOR_WriteProcessMemory_9236 {
  strings:
    $key_9236 = { c5 44 [2] f7 66 [2] f1 53 [2] df 53 [2] e0 4f }

  condition:
    any of them
}