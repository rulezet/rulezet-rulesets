rule TTP_XOR_WriteProcessMemory_9206 {
  strings:
    $key_9206 = { c5 74 [2] f7 56 [2] f1 63 [2] df 63 [2] e0 7f }

  condition:
    any of them
}