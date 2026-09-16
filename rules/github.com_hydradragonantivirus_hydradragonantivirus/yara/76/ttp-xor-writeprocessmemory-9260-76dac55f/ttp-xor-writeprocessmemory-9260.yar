rule TTP_XOR_WriteProcessMemory_9260 {
  strings:
    $key_9260 = { c5 12 [2] f7 30 [2] f1 05 [2] df 05 [2] e0 19 }

  condition:
    any of them
}