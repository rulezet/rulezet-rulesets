rule TTP_XOR_WriteProcessMemory_9b2f {
  strings:
    $key_9b2f = { cc 5d [2] fe 7f [2] f8 4a [2] d6 4a [2] e9 56 }

  condition:
    any of them
}