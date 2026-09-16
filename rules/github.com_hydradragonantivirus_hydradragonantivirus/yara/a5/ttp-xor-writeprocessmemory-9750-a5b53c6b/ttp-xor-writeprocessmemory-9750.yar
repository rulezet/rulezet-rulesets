rule TTP_XOR_WriteProcessMemory_9750 {
  strings:
    $key_9750 = { c0 22 [2] f2 00 [2] f4 35 [2] da 35 [2] e5 29 }

  condition:
    any of them
}