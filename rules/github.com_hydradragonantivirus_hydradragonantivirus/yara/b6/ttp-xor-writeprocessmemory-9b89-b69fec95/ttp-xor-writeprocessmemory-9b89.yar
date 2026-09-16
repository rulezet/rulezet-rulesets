rule TTP_XOR_WriteProcessMemory_9b89 {
  strings:
    $key_9b89 = { cc fb [2] fe d9 [2] f8 ec [2] d6 ec [2] e9 f0 }

  condition:
    any of them
}