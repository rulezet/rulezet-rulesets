rule TTP_XOR_WriteProcessMemory_9008 {
  strings:
    $key_9008 = { c7 7a [2] f5 58 [2] f3 6d [2] dd 6d [2] e2 71 }

  condition:
    any of them
}