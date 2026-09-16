rule TTP_XOR_WriteProcessMemory_9763 {
  strings:
    $key_9763 = { c0 11 [2] f2 33 [2] f4 06 [2] da 06 [2] e5 1a }

  condition:
    any of them
}