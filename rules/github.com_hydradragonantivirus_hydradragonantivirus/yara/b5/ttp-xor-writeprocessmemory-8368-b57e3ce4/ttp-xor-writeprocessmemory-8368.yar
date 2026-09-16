rule TTP_XOR_WriteProcessMemory_8368 {
  strings:
    $key_8368 = { d4 1a [2] e6 38 [2] e0 0d [2] ce 0d [2] f1 11 }

  condition:
    any of them
}