rule TTP_XOR_WriteProcessMemory_8379 {
  strings:
    $key_8379 = { d4 0b [2] e6 29 [2] e0 1c [2] ce 1c [2] f1 00 }

  condition:
    any of them
}