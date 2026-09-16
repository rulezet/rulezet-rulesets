rule TTP_XOR_WriteProcessMemory_9756 {
  strings:
    $key_9756 = { c0 24 [2] f2 06 [2] f4 33 [2] da 33 [2] e5 2f }

  condition:
    any of them
}