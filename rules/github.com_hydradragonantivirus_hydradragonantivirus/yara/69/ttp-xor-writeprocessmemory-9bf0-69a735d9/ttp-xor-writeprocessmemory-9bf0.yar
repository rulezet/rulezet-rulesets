rule TTP_XOR_WriteProcessMemory_9bf0 {
  strings:
    $key_9bf0 = { cc 82 [2] fe a0 [2] f8 95 [2] d6 95 [2] e9 89 }

  condition:
    any of them
}