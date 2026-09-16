rule TTP_XOR_WriteProcessMemory_92fb {
  strings:
    $key_92fb = { c5 89 [2] f7 ab [2] f1 9e [2] df 9e [2] e0 82 }

  condition:
    any of them
}