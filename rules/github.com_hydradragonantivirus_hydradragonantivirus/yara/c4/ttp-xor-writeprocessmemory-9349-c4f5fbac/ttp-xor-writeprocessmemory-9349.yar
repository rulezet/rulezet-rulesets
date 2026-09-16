rule TTP_XOR_WriteProcessMemory_9349 {
  strings:
    $key_9349 = { c4 3b [2] f6 19 [2] f0 2c [2] de 2c [2] e1 30 }

  condition:
    any of them
}