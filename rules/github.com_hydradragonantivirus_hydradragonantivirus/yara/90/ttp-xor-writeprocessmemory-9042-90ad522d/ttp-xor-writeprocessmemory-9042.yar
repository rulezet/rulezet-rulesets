rule TTP_XOR_WriteProcessMemory_9042 {
  strings:
    $key_9042 = { c7 30 [2] f5 12 [2] f3 27 [2] dd 27 [2] e2 3b }

  condition:
    any of them
}