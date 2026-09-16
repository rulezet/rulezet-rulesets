rule TTP_XOR_WriteProcessMemory_9553 {
  strings:
    $key_9553 = { c2 21 [2] f0 03 [2] f6 36 [2] d8 36 [2] e7 2a }

  condition:
    any of them
}