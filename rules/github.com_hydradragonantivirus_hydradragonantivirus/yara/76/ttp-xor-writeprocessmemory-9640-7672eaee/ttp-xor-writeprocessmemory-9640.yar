rule TTP_XOR_WriteProcessMemory_9640 {
  strings:
    $key_9640 = { c1 32 [2] f3 10 [2] f5 25 [2] db 25 [2] e4 39 }

  condition:
    any of them
}