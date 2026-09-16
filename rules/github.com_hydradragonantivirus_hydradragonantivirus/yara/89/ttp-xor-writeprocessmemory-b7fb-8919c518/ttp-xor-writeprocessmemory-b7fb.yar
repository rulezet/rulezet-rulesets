rule TTP_XOR_WriteProcessMemory_b7fb {
  strings:
    $key_b7fb = { e0 89 [2] d2 ab [2] d4 9e [2] fa 9e [2] c5 82 }

  condition:
    any of them
}