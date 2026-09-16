rule TTP_XOR_WriteProcessMemory_9b40 {
  strings:
    $key_9b40 = { cc 32 [2] fe 10 [2] f8 25 [2] d6 25 [2] e9 39 }

  condition:
    any of them
}