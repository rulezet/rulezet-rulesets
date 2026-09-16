rule TTP_XOR_WriteProcessMemory_8308 {
  strings:
    $key_8308 = { d4 7a [2] e6 58 [2] e0 6d [2] ce 6d [2] f1 71 }

  condition:
    any of them
}