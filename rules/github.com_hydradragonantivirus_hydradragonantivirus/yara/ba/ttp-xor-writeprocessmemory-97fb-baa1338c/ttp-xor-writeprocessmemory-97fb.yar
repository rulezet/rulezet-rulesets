rule TTP_XOR_WriteProcessMemory_97fb {
  strings:
    $key_97fb = { c0 89 [2] f2 ab [2] f4 9e [2] da 9e [2] e5 82 }

  condition:
    any of them
}