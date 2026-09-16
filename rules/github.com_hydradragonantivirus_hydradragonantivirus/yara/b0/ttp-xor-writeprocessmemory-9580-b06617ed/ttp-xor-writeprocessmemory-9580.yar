rule TTP_XOR_WriteProcessMemory_9580 {
  strings:
    $key_9580 = { c2 f2 [2] f0 d0 [2] f6 e5 [2] d8 e5 [2] e7 f9 }

  condition:
    any of them
}