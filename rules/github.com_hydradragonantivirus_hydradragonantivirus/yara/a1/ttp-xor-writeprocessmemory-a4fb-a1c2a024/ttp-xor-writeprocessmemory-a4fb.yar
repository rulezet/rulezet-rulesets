rule TTP_XOR_WriteProcessMemory_a4fb {
  strings:
    $key_a4fb = { f3 89 [2] c1 ab [2] c7 9e [2] e9 9e [2] d6 82 }

  condition:
    any of them
}