rule TTP_XOR_WriteProcessMemory_9677 {
  strings:
    $key_9677 = { c1 05 [2] f3 27 [2] f5 12 [2] db 12 [2] e4 0e }

  condition:
    any of them
}