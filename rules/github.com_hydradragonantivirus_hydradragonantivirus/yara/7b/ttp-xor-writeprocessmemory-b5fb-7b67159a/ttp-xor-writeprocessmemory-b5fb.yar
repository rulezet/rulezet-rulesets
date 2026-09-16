rule TTP_XOR_WriteProcessMemory_b5fb {
  strings:
    $key_b5fb = { e2 89 [2] d0 ab [2] d6 9e [2] f8 9e [2] c7 82 }

  condition:
    any of them
}