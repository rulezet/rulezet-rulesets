rule TTP_XOR_WriteProcessMemory_9b06 {
  strings:
    $key_9b06 = { cc 74 [2] fe 56 [2] f8 63 [2] d6 63 [2] e9 7f }

  condition:
    any of them
}