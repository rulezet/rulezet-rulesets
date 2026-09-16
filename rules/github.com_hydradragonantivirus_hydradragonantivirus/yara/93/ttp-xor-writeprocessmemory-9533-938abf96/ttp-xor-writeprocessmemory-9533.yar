rule TTP_XOR_WriteProcessMemory_9533 {
  strings:
    $key_9533 = { c2 41 [2] f0 63 [2] f6 56 [2] d8 56 [2] e7 4a }

  condition:
    any of them
}