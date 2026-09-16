rule TTP_XOR_WriteProcessMemory_9b4c {
  strings:
    $key_9b4c = { cc 3e [2] fe 1c [2] f8 29 [2] d6 29 [2] e9 35 }

  condition:
    any of them
}