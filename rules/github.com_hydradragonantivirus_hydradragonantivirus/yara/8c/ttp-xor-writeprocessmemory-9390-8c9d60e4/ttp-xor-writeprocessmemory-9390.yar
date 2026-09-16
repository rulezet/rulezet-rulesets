rule TTP_XOR_WriteProcessMemory_9390 {
  strings:
    $key_9390 = { c4 e2 [2] f6 c0 [2] f0 f5 [2] de f5 [2] e1 e9 }

  condition:
    any of them
}