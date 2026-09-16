rule TTP_XOR_WriteProcessMemory_9b0d {
  strings:
    $key_9b0d = { cc 7f [2] fe 5d [2] f8 68 [2] d6 68 [2] e9 74 }

  condition:
    any of them
}