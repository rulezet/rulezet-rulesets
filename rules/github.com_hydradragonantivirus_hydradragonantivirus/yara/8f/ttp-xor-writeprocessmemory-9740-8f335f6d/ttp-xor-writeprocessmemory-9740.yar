rule TTP_XOR_WriteProcessMemory_9740 {
  strings:
    $key_9740 = { c0 32 [2] f2 10 [2] f4 25 [2] da 25 [2] e5 39 }

  condition:
    any of them
}