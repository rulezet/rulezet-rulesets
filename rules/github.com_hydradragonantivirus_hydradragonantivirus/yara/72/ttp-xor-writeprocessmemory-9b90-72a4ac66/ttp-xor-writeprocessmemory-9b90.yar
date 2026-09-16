rule TTP_XOR_WriteProcessMemory_9b90 {
  strings:
    $key_9b90 = { cc e2 [2] fe c0 [2] f8 f5 [2] d6 f5 [2] e9 e9 }

  condition:
    any of them
}