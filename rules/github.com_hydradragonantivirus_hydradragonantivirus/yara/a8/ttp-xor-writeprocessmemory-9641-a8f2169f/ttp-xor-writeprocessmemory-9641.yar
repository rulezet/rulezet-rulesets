rule TTP_XOR_WriteProcessMemory_9641 {
  strings:
    $key_9641 = { c1 33 [2] f3 11 [2] f5 24 [2] db 24 [2] e4 38 }

  condition:
    any of them
}