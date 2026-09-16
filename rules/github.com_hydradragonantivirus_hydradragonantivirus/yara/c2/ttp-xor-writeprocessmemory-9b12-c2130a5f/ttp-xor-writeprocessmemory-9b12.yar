rule TTP_XOR_WriteProcessMemory_9b12 {
  strings:
    $key_9b12 = { cc 60 [2] fe 42 [2] f8 77 [2] d6 77 [2] e9 6b }

  condition:
    any of them
}