rule TTP_XOR_WriteProcessMemory_9549 {
  strings:
    $key_9549 = { c2 3b [2] f0 19 [2] f6 2c [2] d8 2c [2] e7 30 }

  condition:
    any of them
}