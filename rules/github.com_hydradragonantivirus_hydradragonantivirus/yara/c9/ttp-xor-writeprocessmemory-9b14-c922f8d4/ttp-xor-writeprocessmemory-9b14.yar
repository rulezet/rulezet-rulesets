rule TTP_XOR_WriteProcessMemory_9b14 {
  strings:
    $key_9b14 = { cc 66 [2] fe 44 [2] f8 71 [2] d6 71 [2] e9 6d }

  condition:
    any of them
}