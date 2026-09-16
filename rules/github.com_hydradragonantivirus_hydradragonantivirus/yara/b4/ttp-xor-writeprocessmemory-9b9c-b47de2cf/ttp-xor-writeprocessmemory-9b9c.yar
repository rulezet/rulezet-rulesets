rule TTP_XOR_WriteProcessMemory_9b9c {
  strings:
    $key_9b9c = { cc ee [2] fe cc [2] f8 f9 [2] d6 f9 [2] e9 e5 }

  condition:
    any of them
}