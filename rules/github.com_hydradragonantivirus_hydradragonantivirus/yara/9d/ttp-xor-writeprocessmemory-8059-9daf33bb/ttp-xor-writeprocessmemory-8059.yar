rule TTP_XOR_WriteProcessMemory_8059 {
  strings:
    $key_8059 = { d7 2b [2] e5 09 [2] e3 3c [2] cd 3c [2] f2 20 }

  condition:
    any of them
}