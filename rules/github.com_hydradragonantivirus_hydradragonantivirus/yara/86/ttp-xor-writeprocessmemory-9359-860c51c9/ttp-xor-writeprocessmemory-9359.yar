rule TTP_XOR_WriteProcessMemory_9359 {
  strings:
    $key_9359 = { c4 2b [2] f6 09 [2] f0 3c [2] de 3c [2] e1 20 }

  condition:
    any of them
}