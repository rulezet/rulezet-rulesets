rule TTP_XOR_WriteProcessMemory_9b05 {
  strings:
    $key_9b05 = { cc 77 [2] fe 55 [2] f8 60 [2] d6 60 [2] e9 7c }

  condition:
    any of them
}