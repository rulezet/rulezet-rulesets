rule TTP_XOR_WriteProcessMemory_9772 {
  strings:
    $key_9772 = { c0 00 [2] f2 22 [2] f4 17 [2] da 17 [2] e5 0b }

  condition:
    any of them
}