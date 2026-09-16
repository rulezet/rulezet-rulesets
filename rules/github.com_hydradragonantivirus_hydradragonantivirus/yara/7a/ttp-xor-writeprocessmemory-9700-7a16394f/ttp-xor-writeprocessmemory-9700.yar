rule TTP_XOR_WriteProcessMemory_9700 {
  strings:
    $key_9700 = { c0 72 [2] f2 50 [2] f4 65 [2] da 65 [2] e5 79 }

  condition:
    any of them
}