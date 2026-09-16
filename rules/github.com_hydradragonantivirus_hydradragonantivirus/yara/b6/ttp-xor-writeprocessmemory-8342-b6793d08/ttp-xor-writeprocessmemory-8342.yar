rule TTP_XOR_WriteProcessMemory_8342 {
  strings:
    $key_8342 = { d4 30 [2] e6 12 [2] e0 27 [2] ce 27 [2] f1 3b }

  condition:
    any of them
}