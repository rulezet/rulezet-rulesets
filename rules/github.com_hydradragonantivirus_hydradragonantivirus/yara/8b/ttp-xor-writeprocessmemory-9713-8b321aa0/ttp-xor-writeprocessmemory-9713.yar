rule TTP_XOR_WriteProcessMemory_9713 {
  strings:
    $key_9713 = { c0 61 [2] f2 43 [2] f4 76 [2] da 76 [2] e5 6a }

  condition:
    any of them
}