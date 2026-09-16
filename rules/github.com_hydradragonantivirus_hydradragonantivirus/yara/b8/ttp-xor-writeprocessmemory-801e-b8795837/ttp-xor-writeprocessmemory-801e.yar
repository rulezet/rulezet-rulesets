rule TTP_XOR_WriteProcessMemory_801e {
  strings:
    $key_801e = { d7 6c [2] e5 4e [2] e3 7b [2] cd 7b [2] f2 67 }

  condition:
    any of them
}