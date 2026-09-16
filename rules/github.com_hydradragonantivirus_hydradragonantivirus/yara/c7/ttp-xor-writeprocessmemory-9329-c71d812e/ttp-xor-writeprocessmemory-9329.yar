rule TTP_XOR_WriteProcessMemory_9329 {
  strings:
    $key_9329 = { c4 5b [2] f6 79 [2] f0 4c [2] de 4c [2] e1 50 }

  condition:
    any of them
}