rule TTP_XOR_WriteProcessMemory_9168 {
  strings:
    $key_9168 = { c6 1a [2] f4 38 [2] f2 0d [2] dc 0d [2] e3 11 }

  condition:
    any of them
}