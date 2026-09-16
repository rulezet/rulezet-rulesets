rule TTP_XOR_WriteProcessMemory_9b81 {
  strings:
    $key_9b81 = { cc f3 [2] fe d1 [2] f8 e4 [2] d6 e4 [2] e9 f8 }

  condition:
    any of them
}