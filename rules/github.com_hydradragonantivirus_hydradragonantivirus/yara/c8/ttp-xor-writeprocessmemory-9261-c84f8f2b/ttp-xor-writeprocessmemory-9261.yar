rule TTP_XOR_WriteProcessMemory_9261 {
  strings:
    $key_9261 = { c5 13 [2] f7 31 [2] f1 04 [2] df 04 [2] e0 18 }

  condition:
    any of them
}