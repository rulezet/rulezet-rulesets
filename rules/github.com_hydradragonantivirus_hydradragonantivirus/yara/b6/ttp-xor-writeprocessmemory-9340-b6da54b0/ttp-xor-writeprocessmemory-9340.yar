rule TTP_XOR_WriteProcessMemory_9340 {
  strings:
    $key_9340 = { c4 32 [2] f6 10 [2] f0 25 [2] de 25 [2] e1 39 }

  condition:
    any of them
}