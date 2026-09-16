rule TTP_XOR_WriteProcessMemory_9530 {
  strings:
    $key_9530 = { c2 42 [2] f0 60 [2] f6 55 [2] d8 55 [2] e7 49 }

  condition:
    any of them
}