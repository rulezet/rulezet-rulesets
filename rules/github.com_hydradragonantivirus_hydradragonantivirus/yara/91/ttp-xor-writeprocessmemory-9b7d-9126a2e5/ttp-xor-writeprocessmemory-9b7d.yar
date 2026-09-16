rule TTP_XOR_WriteProcessMemory_9b7d {
  strings:
    $key_9b7d = { cc 0f [2] fe 2d [2] f8 18 [2] d6 18 [2] e9 04 }

  condition:
    any of them
}