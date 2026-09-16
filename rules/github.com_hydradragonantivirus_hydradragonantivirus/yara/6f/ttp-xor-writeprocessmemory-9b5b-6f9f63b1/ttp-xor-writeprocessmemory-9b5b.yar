rule TTP_XOR_WriteProcessMemory_9b5b {
  strings:
    $key_9b5b = { cc 29 [2] fe 0b [2] f8 3e [2] d6 3e [2] e9 22 }

  condition:
    any of them
}