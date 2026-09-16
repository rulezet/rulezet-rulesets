rule TTP_XOR_WriteProcessMemory_9722 {
  strings:
    $key_9722 = { c0 50 [2] f2 72 [2] f4 47 [2] da 47 [2] e5 5b }

  condition:
    any of them
}