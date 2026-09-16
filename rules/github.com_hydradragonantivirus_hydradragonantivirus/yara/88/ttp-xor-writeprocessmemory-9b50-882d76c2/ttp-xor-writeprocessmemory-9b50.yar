rule TTP_XOR_WriteProcessMemory_9b50 {
  strings:
    $key_9b50 = { cc 22 [2] fe 00 [2] f8 35 [2] d6 35 [2] e9 29 }

  condition:
    any of them
}