rule TTP_XOR_WriteProcessMemory_9b6d {
  strings:
    $key_9b6d = { cc 1f [2] fe 3d [2] f8 08 [2] d6 08 [2] e9 14 }

  condition:
    any of them
}