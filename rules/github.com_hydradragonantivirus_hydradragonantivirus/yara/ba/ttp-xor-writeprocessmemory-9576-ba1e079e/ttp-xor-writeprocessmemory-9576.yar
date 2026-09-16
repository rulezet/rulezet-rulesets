rule TTP_XOR_WriteProcessMemory_9576 {
  strings:
    $key_9576 = { c2 04 [2] f0 26 [2] f6 13 [2] d8 13 [2] e7 0f }

  condition:
    any of them
}