rule TTP_XOR_WriteProcessMemory_9629 {
  strings:
    $key_9629 = { c1 5b [2] f3 79 [2] f5 4c [2] db 4c [2] e4 50 }

  condition:
    any of them
}