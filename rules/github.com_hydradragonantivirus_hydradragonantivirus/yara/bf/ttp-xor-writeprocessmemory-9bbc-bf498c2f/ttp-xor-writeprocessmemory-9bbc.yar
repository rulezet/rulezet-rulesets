rule TTP_XOR_WriteProcessMemory_9bbc {
  strings:
    $key_9bbc = { cc ce [2] fe ec [2] f8 d9 [2] d6 d9 [2] e9 c5 }

  condition:
    any of them
}