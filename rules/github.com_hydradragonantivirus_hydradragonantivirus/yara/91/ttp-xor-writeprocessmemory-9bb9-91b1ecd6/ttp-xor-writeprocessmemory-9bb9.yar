rule TTP_XOR_WriteProcessMemory_9bb9 {
  strings:
    $key_9bb9 = { cc cb [2] fe e9 [2] f8 dc [2] d6 dc [2] e9 c0 }

  condition:
    any of them
}