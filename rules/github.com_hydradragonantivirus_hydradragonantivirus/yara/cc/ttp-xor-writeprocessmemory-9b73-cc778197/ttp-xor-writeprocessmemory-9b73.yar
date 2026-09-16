rule TTP_XOR_WriteProcessMemory_9b73 {
  strings:
    $key_9b73 = { cc 01 [2] fe 23 [2] f8 16 [2] d6 16 [2] e9 0a }

  condition:
    any of them
}