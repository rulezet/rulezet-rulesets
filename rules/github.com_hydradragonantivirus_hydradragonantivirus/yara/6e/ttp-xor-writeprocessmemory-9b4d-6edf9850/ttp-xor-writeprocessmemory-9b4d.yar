rule TTP_XOR_WriteProcessMemory_9b4d {
  strings:
    $key_9b4d = { cc 3f [2] fe 1d [2] f8 28 [2] d6 28 [2] e9 34 }

  condition:
    any of them
}