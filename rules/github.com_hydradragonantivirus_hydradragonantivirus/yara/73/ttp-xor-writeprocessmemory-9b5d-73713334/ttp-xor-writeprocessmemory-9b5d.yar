rule TTP_XOR_WriteProcessMemory_9b5d {
  strings:
    $key_9b5d = { cc 2f [2] fe 0d [2] f8 38 [2] d6 38 [2] e9 24 }

  condition:
    any of them
}