rule TTP_XOR_WriteProcessMemory_9b25 {
  strings:
    $key_9b25 = { cc 57 [2] fe 75 [2] f8 40 [2] d6 40 [2] e9 5c }

  condition:
    any of them
}