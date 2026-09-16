rule TTP_XOR_WriteProcessMemory_9150 {
  strings:
    $key_9150 = { c6 22 [2] f4 00 [2] f2 35 [2] dc 35 [2] e3 29 }

  condition:
    any of them
}