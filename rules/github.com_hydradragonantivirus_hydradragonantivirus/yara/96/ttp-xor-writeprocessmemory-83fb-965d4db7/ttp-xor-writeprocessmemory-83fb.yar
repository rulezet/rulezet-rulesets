rule TTP_XOR_WriteProcessMemory_83fb {
  strings:
    $key_83fb = { d4 89 [2] e6 ab [2] e0 9e [2] ce 9e [2] f1 82 }

  condition:
    any of them
}