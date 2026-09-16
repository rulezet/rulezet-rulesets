rule TTP_XOR_WriteProcessMemory_9b66 {
  strings:
    $key_9b66 = { cc 14 [2] fe 36 [2] f8 03 [2] d6 03 [2] e9 1f }

  condition:
    any of them
}