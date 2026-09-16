rule TTP_XOR_WriteProcessMemory_9546 {
  strings:
    $key_9546 = { c2 34 [2] f0 16 [2] f6 23 [2] d8 23 [2] e7 3f }

  condition:
    any of them
}