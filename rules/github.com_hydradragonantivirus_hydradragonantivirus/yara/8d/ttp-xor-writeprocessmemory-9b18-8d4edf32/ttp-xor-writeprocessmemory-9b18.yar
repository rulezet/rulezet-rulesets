rule TTP_XOR_WriteProcessMemory_9b18 {
  strings:
    $key_9b18 = { cc 6a [2] fe 48 [2] f8 7d [2] d6 7d [2] e9 61 }

  condition:
    any of them
}