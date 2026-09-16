rule TTP_XOR_WriteProcessMemory_9760 {
  strings:
    $key_9760 = { c0 12 [2] f2 30 [2] f4 05 [2] da 05 [2] e5 19 }

  condition:
    any of them
}