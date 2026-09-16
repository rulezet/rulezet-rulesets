rule TTP_XOR_WriteProcessMemory_9550 {
  strings:
    $key_9550 = { c2 22 [2] f0 00 [2] f6 35 [2] d8 35 [2] e7 29 }

  condition:
    any of them
}