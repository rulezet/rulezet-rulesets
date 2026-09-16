rule TTP_XOR_WriteProcessMemory_9249 {
  strings:
    $key_9249 = { c5 3b [2] f7 19 [2] f1 2c [2] df 2c [2] e0 30 }

  condition:
    any of them
}