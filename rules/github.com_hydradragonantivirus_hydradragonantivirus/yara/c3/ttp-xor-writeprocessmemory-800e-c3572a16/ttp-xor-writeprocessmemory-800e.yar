rule TTP_XOR_WriteProcessMemory_800e {
  strings:
    $key_800e = { d7 7c [2] e5 5e [2] e3 6b [2] cd 6b [2] f2 77 }

  condition:
    any of them
}