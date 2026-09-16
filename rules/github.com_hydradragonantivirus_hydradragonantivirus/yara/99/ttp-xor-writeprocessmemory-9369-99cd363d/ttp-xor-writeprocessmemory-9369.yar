rule TTP_XOR_WriteProcessMemory_9369 {
  strings:
    $key_9369 = { c4 1b [2] f6 39 [2] f0 0c [2] de 0c [2] e1 10 }

  condition:
    any of them
}