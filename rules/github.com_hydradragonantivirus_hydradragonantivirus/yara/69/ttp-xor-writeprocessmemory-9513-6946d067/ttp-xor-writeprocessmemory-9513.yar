rule TTP_XOR_WriteProcessMemory_9513 {
  strings:
    $key_9513 = { c2 61 [2] f0 43 [2] f6 76 [2] d8 76 [2] e7 6a }

  condition:
    any of them
}