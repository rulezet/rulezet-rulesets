rule TTP_XOR_WriteProcessMemory_9309 {
  strings:
    $key_9309 = { c4 7b [2] f6 59 [2] f0 6c [2] de 6c [2] e1 70 }

  condition:
    any of them
}