rule TTP_XOR_WriteProcessMemory_9360 {
  strings:
    $key_9360 = { c4 12 [2] f6 30 [2] f0 05 [2] de 05 [2] e1 19 }

  condition:
    any of them
}