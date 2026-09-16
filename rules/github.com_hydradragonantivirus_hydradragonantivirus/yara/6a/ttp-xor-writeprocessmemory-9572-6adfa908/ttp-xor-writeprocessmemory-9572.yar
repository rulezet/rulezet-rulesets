rule TTP_XOR_WriteProcessMemory_9572 {
  strings:
    $key_9572 = { c2 00 [2] f0 22 [2] f6 17 [2] d8 17 [2] e7 0b }

  condition:
    any of them
}