rule TTP_XOR_WriteProcessMemory_e7fb {
  strings:
    $key_e7fb = { b0 89 [2] 82 ab [2] 84 9e [2] aa 9e [2] 95 82 }

  condition:
    any of them
}