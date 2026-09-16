rule TTP_XOR_WriteProcessMemory_80e9 {
  strings:
    $key_80e9 = { d7 9b [2] e5 b9 [2] e3 8c [2] cd 8c [2] f2 90 }

  condition:
    any of them
}