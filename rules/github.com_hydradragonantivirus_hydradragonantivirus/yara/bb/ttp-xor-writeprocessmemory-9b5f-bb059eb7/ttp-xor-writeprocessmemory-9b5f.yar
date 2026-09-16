rule TTP_XOR_WriteProcessMemory_9b5f {
  strings:
    $key_9b5f = { cc 2d [2] fe 0f [2] f8 3a [2] d6 3a [2] e9 26 }

  condition:
    any of them
}