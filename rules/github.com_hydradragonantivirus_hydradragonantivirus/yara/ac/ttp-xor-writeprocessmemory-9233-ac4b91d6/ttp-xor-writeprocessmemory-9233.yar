rule TTP_XOR_WriteProcessMemory_9233 {
  strings:
    $key_9233 = { c5 41 [2] f7 63 [2] f1 56 [2] df 56 [2] e0 4a }

  condition:
    any of them
}