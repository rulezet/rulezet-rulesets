rule TTP_XOR_WriteProcessMemory_9bf1 {
  strings:
    $key_9bf1 = { cc 83 [2] fe a1 [2] f8 94 [2] d6 94 [2] e9 88 }

  condition:
    any of them
}