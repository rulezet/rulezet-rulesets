rule TTP_XOR_WriteProcessMemory_9582 {
  strings:
    $key_9582 = { c2 f0 [2] f0 d2 [2] f6 e7 [2] d8 e7 [2] e7 fb }

  condition:
    any of them
}