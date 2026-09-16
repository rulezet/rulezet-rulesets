rule TTP_XOR_WriteProcessMemory_803e {
  strings:
    $key_803e = { d7 4c [2] e5 6e [2] e3 5b [2] cd 5b [2] f2 47 }

  condition:
    any of them
}