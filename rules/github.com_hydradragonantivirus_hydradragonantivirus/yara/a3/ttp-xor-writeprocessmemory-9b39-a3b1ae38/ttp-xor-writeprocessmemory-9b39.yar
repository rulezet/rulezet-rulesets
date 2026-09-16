rule TTP_XOR_WriteProcessMemory_9b39 {
  strings:
    $key_9b39 = { cc 4b [2] fe 69 [2] f8 5c [2] d6 5c [2] e9 40 }

  condition:
    any of them
}