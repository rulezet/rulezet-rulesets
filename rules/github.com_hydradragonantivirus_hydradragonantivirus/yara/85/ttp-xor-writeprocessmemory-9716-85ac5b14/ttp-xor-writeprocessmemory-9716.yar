rule TTP_XOR_WriteProcessMemory_9716 {
  strings:
    $key_9716 = { c0 64 [2] f2 46 [2] f4 73 [2] da 73 [2] e5 6f }

  condition:
    any of them
}