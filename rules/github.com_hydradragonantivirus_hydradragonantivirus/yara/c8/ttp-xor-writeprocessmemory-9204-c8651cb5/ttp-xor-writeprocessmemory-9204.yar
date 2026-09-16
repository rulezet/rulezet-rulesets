rule TTP_XOR_WriteProcessMemory_9204 {
  strings:
    $key_9204 = { c5 76 [2] f7 54 [2] f1 61 [2] df 61 [2] e0 7d }

  condition:
    any of them
}