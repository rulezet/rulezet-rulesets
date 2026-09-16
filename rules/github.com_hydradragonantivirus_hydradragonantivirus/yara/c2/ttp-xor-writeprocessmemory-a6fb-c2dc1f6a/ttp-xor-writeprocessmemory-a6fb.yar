rule TTP_XOR_WriteProcessMemory_a6fb {
  strings:
    $key_a6fb = { f1 89 [2] c3 ab [2] c5 9e [2] eb 9e [2] d4 82 }

  condition:
    any of them
}