rule TTP_XOR_WriteProcessMemory_9bf7 {
  strings:
    $key_9bf7 = { cc 85 [2] fe a7 [2] f8 92 [2] d6 92 [2] e9 8e }

  condition:
    any of them
}