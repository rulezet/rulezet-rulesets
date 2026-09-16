rule TTP_XOR_WriteProcessMemory_9391 {
  strings:
    $key_9391 = { c4 e3 [2] f6 c1 [2] f0 f4 [2] de f4 [2] e1 e8 }

  condition:
    any of them
}