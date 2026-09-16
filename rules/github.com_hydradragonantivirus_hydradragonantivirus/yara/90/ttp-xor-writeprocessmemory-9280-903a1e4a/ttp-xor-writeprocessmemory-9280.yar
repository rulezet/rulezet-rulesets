rule TTP_XOR_WriteProcessMemory_9280 {
  strings:
    $key_9280 = { c5 f2 [2] f7 d0 [2] f1 e5 [2] df e5 [2] e0 f9 }

  condition:
    any of them
}