rule TTP_XOR_WriteProcessMemory_9749 {
  strings:
    $key_9749 = { c0 3b [2] f2 19 [2] f4 2c [2] da 2c [2] e5 30 }

  condition:
    any of them
}