rule TTP_XOR_WriteProcessMemory_9b41 {
  strings:
    $key_9b41 = { cc 33 [2] fe 11 [2] f8 24 [2] d6 24 [2] e9 38 }

  condition:
    any of them
}