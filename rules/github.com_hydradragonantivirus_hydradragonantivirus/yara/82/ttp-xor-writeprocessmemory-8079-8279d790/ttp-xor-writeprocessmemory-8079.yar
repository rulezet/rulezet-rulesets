rule TTP_XOR_WriteProcessMemory_8079 {
  strings:
    $key_8079 = { d7 0b [2] e5 29 [2] e3 1c [2] cd 1c [2] f2 00 }

  condition:
    any of them
}