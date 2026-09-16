rule TTP_XOR_WriteProcessMemory_9b3d {
  strings:
    $key_9b3d = { cc 4f [2] fe 6d [2] f8 58 [2] d6 58 [2] e9 44 }

  condition:
    any of them
}