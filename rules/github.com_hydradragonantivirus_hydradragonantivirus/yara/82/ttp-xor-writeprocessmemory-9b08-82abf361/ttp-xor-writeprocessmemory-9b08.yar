rule TTP_XOR_WriteProcessMemory_9b08 {
  strings:
    $key_9b08 = { cc 7a [2] fe 58 [2] f8 6d [2] d6 6d [2] e9 71 }

  condition:
    any of them
}