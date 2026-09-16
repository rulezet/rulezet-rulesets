rule TTP_XOR_WriteProcessMemory_9b33 {
  strings:
    $key_9b33 = { cc 41 [2] fe 63 [2] f8 56 [2] d6 56 [2] e9 4a }

  condition:
    any of them
}