rule TTP_XOR_WriteProcessMemory_9bf8 {
  strings:
    $key_9bf8 = { cc 8a [2] fe a8 [2] f8 9d [2] d6 9d [2] e9 81 }

  condition:
    any of them
}