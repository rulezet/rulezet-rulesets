rule TTP_XOR_WriteProcessMemory_9773 {
  strings:
    $key_9773 = { c0 01 [2] f2 23 [2] f4 16 [2] da 16 [2] e5 0a }

  condition:
    any of them
}