rule TTP_XOR_WriteProcessMemory_9767 {
  strings:
    $key_9767 = { c0 15 [2] f2 37 [2] f4 02 [2] da 02 [2] e5 1e }

  condition:
    any of them
}