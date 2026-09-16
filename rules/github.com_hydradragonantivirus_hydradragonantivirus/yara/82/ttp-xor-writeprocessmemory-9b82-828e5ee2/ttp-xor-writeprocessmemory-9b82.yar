rule TTP_XOR_WriteProcessMemory_9b82 {
  strings:
    $key_9b82 = { cc f0 [2] fe d2 [2] f8 e7 [2] d6 e7 [2] e9 fb }

  condition:
    any of them
}