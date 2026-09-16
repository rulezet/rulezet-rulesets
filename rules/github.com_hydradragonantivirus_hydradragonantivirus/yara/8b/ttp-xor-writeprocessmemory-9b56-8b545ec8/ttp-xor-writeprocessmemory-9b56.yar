rule TTP_XOR_WriteProcessMemory_9b56 {
  strings:
    $key_9b56 = { cc 24 [2] fe 06 [2] f8 33 [2] d6 33 [2] e9 2f }

  condition:
    any of them
}