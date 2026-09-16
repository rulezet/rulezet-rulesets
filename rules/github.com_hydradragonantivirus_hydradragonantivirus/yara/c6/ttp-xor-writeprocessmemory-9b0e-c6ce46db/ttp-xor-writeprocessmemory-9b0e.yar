rule TTP_XOR_WriteProcessMemory_9b0e {
  strings:
    $key_9b0e = { cc 7c [2] fe 5e [2] f8 6b [2] d6 6b [2] e9 77 }

  condition:
    any of them
}