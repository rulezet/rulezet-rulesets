rule TTP_XOR_WriteProcessMemory_9b45 {
  strings:
    $key_9b45 = { cc 37 [2] fe 15 [2] f8 20 [2] d6 20 [2] e9 3c }

  condition:
    any of them
}