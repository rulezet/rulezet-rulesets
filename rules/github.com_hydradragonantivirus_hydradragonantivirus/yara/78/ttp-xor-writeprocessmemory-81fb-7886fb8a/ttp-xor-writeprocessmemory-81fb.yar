rule TTP_XOR_WriteProcessMemory_81fb {
  strings:
    $key_81fb = { d6 89 [2] e4 ab [2] e2 9e [2] cc 9e [2] f3 82 }

  condition:
    any of them
}