rule TTP_XOR_WriteProcessMemory_8349 {
  strings:
    $key_8349 = { d4 3b [2] e6 19 [2] e0 2c [2] ce 2c [2] f1 30 }

  condition:
    any of them
}