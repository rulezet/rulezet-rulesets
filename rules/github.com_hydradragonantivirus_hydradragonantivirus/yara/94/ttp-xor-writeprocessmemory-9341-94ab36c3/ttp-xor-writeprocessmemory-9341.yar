rule TTP_XOR_WriteProcessMemory_9341 {
  strings:
    $key_9341 = { c4 33 [2] f6 11 [2] f0 24 [2] de 24 [2] e1 38 }

  condition:
    any of them
}