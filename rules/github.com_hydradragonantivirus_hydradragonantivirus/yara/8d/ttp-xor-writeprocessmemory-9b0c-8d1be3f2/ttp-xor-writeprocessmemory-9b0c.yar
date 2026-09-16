rule TTP_XOR_WriteProcessMemory_9b0c {
  strings:
    $key_9b0c = { cc 7e [2] fe 5c [2] f8 69 [2] d6 69 [2] e9 75 }

  condition:
    any of them
}