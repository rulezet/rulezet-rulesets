rule TTP_XOR_WriteProcessMemory_9b22 {
  strings:
    $key_9b22 = { cc 50 [2] fe 72 [2] f8 47 [2] d6 47 [2] e9 5b }

  condition:
    any of them
}