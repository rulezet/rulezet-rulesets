rule TTP_XOR_WriteProcessMemory_9b77 {
  strings:
    $key_9b77 = { cc 05 [2] fe 27 [2] f8 12 [2] d6 12 [2] e9 0e }

  condition:
    any of them
}