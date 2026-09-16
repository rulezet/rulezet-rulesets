rule TTP_XOR_WriteProcessMemory_9643 {
  strings:
    $key_9643 = { c1 31 [2] f3 13 [2] f5 26 [2] db 26 [2] e4 3a }

  condition:
    any of them
}