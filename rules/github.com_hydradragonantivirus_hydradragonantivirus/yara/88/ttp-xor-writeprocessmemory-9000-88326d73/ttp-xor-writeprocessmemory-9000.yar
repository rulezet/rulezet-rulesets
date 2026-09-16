rule TTP_XOR_WriteProcessMemory_9000 {
  strings:
    $key_9000 = { c7 72 [2] f5 50 [2] f3 65 [2] dd 65 [2] e2 79 }

  condition:
    any of them
}