rule TTP_XOR_WriteProcessMemory_9b6e {
  strings:
    $key_9b6e = { cc 1c [2] fe 3e [2] f8 0b [2] d6 0b [2] e9 17 }

  condition:
    any of them
}