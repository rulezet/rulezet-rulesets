rule TTP_XOR_WriteProcessMemory_9bf6 {
  strings:
    $key_9bf6 = { cc 84 [2] fe a6 [2] f8 93 [2] d6 93 [2] e9 8f }

  condition:
    any of them
}