rule TTP_XOR_WriteProcessMemory_9b79 {
  strings:
    $key_9b79 = { cc 0b [2] fe 29 [2] f8 1c [2] d6 1c [2] e9 00 }

  condition:
    any of them
}