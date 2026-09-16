rule TTP_XOR_WriteProcessMemory_9b0f {
  strings:
    $key_9b0f = { cc 7d [2] fe 5f [2] f8 6a [2] d6 6a [2] e9 76 }

  condition:
    any of them
}