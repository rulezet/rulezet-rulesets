rule TTP_XOR_WriteProcessMemory_9512 {
  strings:
    $key_9512 = { c2 60 [2] f0 42 [2] f6 77 [2] d8 77 [2] e7 6b }

  condition:
    any of them
}