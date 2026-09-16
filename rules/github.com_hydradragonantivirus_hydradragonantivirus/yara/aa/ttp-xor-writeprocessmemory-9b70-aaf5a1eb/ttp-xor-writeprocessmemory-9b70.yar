rule TTP_XOR_WriteProcessMemory_9b70 {
  strings:
    $key_9b70 = { cc 02 [2] fe 20 [2] f8 15 [2] d6 15 [2] e9 09 }

  condition:
    any of them
}