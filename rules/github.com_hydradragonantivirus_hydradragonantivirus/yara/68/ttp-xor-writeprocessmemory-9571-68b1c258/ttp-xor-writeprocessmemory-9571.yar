rule TTP_XOR_WriteProcessMemory_9571 {
  strings:
    $key_9571 = { c2 03 [2] f0 21 [2] f6 14 [2] d8 14 [2] e7 08 }

  condition:
    any of them
}