rule TTP_XOR_WriteProcessMemory_9079 {
  strings:
    $key_9079 = { c7 0b [2] f5 29 [2] f3 1c [2] dd 1c [2] e2 00 }

  condition:
    any of them
}