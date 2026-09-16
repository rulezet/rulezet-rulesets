rule TTP_XOR_WriteProcessMemory_9b1d {
  strings:
    $key_9b1d = { cc 6f [2] fe 4d [2] f8 78 [2] d6 78 [2] e9 64 }

  condition:
    any of them
}