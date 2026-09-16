rule TTP_XOR_WriteProcessMemory_9350 {
  strings:
    $key_9350 = { c4 22 [2] f6 00 [2] f0 35 [2] de 35 [2] e1 29 }

  condition:
    any of them
}