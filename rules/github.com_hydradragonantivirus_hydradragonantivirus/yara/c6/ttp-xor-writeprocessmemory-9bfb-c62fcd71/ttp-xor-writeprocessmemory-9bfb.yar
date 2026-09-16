rule TTP_XOR_WriteProcessMemory_9bfb {
  strings:
    $key_9bfb = { cc 89 [2] fe ab [2] f8 9e [2] d6 9e [2] e9 82 }

  condition:
    any of them
}