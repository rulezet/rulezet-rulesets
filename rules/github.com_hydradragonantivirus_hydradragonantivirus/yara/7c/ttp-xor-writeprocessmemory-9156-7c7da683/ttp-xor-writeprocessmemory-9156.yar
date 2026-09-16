rule TTP_XOR_WriteProcessMemory_9156 {
  strings:
    $key_9156 = { c6 24 [2] f4 06 [2] f2 33 [2] dc 33 [2] e3 2f }

  condition:
    any of them
}