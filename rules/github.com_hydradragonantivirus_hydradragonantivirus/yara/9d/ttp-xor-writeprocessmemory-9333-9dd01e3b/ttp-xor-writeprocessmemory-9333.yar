rule TTP_XOR_WriteProcessMemory_9333 {
  strings:
    $key_9333 = { c4 41 [2] f6 63 [2] f0 56 [2] de 56 [2] e1 4a }

  condition:
    any of them
}