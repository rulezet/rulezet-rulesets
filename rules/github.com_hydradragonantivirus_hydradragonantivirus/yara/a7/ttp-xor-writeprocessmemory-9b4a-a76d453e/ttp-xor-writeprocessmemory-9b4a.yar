rule TTP_XOR_WriteProcessMemory_9b4a {
  strings:
    $key_9b4a = { cc 38 [2] fe 1a [2] f8 2f [2] d6 2f [2] e9 33 }

  condition:
    any of them
}