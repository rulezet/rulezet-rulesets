rule TTP_XOR_WriteProcessMemory_9b1e {
  strings:
    $key_9b1e = { cc 6c [2] fe 4e [2] f8 7b [2] d6 7b [2] e9 67 }

  condition:
    any of them
}