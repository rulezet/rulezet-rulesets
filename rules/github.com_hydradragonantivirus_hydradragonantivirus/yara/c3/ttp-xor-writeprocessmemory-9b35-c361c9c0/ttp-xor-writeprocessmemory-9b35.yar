rule TTP_XOR_WriteProcessMemory_9b35 {
  strings:
    $key_9b35 = { cc 47 [2] fe 65 [2] f8 50 [2] d6 50 [2] e9 4c }

  condition:
    any of them
}