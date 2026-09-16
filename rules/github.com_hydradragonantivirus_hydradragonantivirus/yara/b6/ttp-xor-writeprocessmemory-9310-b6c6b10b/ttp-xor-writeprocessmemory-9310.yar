rule TTP_XOR_WriteProcessMemory_9310 {
  strings:
    $key_9310 = { c4 62 [2] f6 40 [2] f0 75 [2] de 75 [2] e1 69 }

  condition:
    any of them
}