rule TTP_XOR_WriteProcessMemory_9702 {
  strings:
    $key_9702 = { c0 70 [2] f2 52 [2] f4 67 [2] da 67 [2] e5 7b }

  condition:
    any of them
}