rule TTP_XOR_WriteProcessMemory_9706 {
  strings:
    $key_9706 = { c0 74 [2] f2 56 [2] f4 63 [2] da 63 [2] e5 7f }

  condition:
    any of them
}