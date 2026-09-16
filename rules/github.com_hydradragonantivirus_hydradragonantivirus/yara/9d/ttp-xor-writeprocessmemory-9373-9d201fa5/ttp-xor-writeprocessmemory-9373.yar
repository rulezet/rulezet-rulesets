rule TTP_XOR_WriteProcessMemory_9373 {
  strings:
    $key_9373 = { c4 01 [2] f6 23 [2] f0 16 [2] de 16 [2] e1 0a }

  condition:
    any of them
}