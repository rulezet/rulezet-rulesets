rule TTP_XOR_WriteProcessMemory_9336 {
  strings:
    $key_9336 = { c4 44 [2] f6 66 [2] f0 53 [2] de 53 [2] e1 4f }

  condition:
    any of them
}