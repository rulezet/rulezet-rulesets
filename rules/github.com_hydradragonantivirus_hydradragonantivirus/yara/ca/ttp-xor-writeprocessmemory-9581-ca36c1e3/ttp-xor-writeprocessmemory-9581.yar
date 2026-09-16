rule TTP_XOR_WriteProcessMemory_9581 {
  strings:
    $key_9581 = { c2 f3 [2] f0 d1 [2] f6 e4 [2] d8 e4 [2] e7 f8 }

  condition:
    any of them
}