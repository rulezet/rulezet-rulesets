rule TTP_XOR_WriteProcessMemory_9b2a {
  strings:
    $key_9b2a = { cc 58 [2] fe 7a [2] f8 4f [2] d6 4f [2] e9 53 }

  condition:
    any of them
}