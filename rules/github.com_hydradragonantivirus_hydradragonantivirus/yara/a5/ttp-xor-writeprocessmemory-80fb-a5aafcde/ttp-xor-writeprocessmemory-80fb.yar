rule TTP_XOR_WriteProcessMemory_80fb {
  strings:
    $key_80fb = { d7 89 [2] e5 ab [2] e3 9e [2] cd 9e [2] f2 82 }

  condition:
    any of them
}