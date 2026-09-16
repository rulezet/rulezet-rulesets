rule TTP_XOR_WriteProcessMemory_8009 {
  strings:
    $key_8009 = { d7 7b [2] e5 59 [2] e3 6c [2] cd 6c [2] f2 70 }

  condition:
    any of them
}