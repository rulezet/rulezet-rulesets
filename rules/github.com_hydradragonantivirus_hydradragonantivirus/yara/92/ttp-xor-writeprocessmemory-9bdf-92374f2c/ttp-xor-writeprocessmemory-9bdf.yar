rule TTP_XOR_WriteProcessMemory_9bdf {
  strings:
    $key_9bdf = { cc ad [2] fe 8f [2] f8 ba [2] d6 ba [2] e9 a6 }

  condition:
    any of them
}