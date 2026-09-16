rule TTP_XOR_WriteProcessMemory_9bf5 {
  strings:
    $key_9bf5 = { cc 87 [2] fe a5 [2] f8 90 [2] d6 90 [2] e9 8c }

  condition:
    any of them
}