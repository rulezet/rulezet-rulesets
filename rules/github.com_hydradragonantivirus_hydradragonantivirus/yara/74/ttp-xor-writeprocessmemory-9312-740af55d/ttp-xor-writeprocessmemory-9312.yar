rule TTP_XOR_WriteProcessMemory_9312 {
  strings:
    $key_9312 = { c4 60 [2] f6 42 [2] f0 77 [2] de 77 [2] e1 6b }

  condition:
    any of them
}