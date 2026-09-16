rule TTP_XOR_WriteProcessMemory_8362 {
  strings:
    $key_8362 = { d4 10 [2] e6 32 [2] e0 07 [2] ce 07 [2] f1 1b }

  condition:
    any of them
}