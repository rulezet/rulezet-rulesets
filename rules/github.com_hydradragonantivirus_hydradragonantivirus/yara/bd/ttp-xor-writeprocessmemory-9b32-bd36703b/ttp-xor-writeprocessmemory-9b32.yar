rule TTP_XOR_WriteProcessMemory_9b32 {
  strings:
    $key_9b32 = { cc 40 [2] fe 62 [2] f8 57 [2] d6 57 [2] e9 4b }

  condition:
    any of them
}