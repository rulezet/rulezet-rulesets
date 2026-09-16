rule TTP_XOR_WriteProcessMemory_9552 {
  strings:
    $key_9552 = { c2 20 [2] f0 02 [2] f6 37 [2] d8 37 [2] e7 2b }

  condition:
    any of them
}