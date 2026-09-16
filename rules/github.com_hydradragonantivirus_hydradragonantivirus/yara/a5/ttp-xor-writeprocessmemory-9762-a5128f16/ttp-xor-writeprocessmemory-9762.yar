rule TTP_XOR_WriteProcessMemory_9762 {
  strings:
    $key_9762 = { c0 10 [2] f2 32 [2] f4 07 [2] da 07 [2] e5 1b }

  condition:
    any of them
}