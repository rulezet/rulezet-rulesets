rule TTP_XOR_WriteProcessMemory_9348 {
  strings:
    $key_9348 = { c4 3a [2] f6 18 [2] f0 2d [2] de 2d [2] e1 31 }

  condition:
    any of them
}