rule TTP_XOR_WriteProcessMemory_9b7e {
  strings:
    $key_9b7e = { cc 0c [2] fe 2e [2] f8 1b [2] d6 1b [2] e9 07 }

  condition:
    any of them
}