rule TTP_XOR_WriteProcessMemory_9727 {
  strings:
    $key_9727 = { c0 55 [2] f2 77 [2] f4 42 [2] da 42 [2] e5 5e }

  condition:
    any of them
}