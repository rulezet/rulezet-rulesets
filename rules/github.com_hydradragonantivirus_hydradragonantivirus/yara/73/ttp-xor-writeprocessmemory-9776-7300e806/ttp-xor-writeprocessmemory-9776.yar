rule TTP_XOR_WriteProcessMemory_9776 {
  strings:
    $key_9776 = { c0 04 [2] f2 26 [2] f4 13 [2] da 13 [2] e5 0f }

  condition:
    any of them
}