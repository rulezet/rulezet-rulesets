rule TTP_XOR_WriteProcessMemory_9481 {
  strings:
    $key_9481 = { c3 f3 [2] f1 d1 [2] f7 e4 [2] d9 e4 [2] e6 f8 }

  condition:
    any of them
}