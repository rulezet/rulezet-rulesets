rule TTP_XOR_WriteProcessMemory_9068 {
  strings:
    $key_9068 = { c7 1a [2] f5 38 [2] f3 0d [2] dd 0d [2] e2 11 }

  condition:
    any of them
}