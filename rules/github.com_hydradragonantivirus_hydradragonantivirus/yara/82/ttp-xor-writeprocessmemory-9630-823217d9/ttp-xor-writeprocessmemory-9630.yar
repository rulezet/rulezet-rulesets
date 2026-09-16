rule TTP_XOR_WriteProcessMemory_9630 {
  strings:
    $key_9630 = { c1 42 [2] f3 60 [2] f5 55 [2] db 55 [2] e4 49 }

  condition:
    any of them
}