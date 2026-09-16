rule TTP_XOR_WriteProcessMemory_9b9b {
  strings:
    $key_9b9b = { cc e9 [2] fe cb [2] f8 fe [2] d6 fe [2] e9 e2 }

  condition:
    any of them
}