rule TTP_XOR_WriteProcessMemory_9b10 {
  strings:
    $key_9b10 = { cc 62 [2] fe 40 [2] f8 75 [2] d6 75 [2] e9 69 }

  condition:
    any of them
}