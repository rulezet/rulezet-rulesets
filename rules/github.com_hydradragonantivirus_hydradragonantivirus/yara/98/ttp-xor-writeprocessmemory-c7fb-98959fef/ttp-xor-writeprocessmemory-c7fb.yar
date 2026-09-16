rule TTP_XOR_WriteProcessMemory_c7fb {
  strings:
    $key_c7fb = { 90 89 [2] a2 ab [2] a4 9e [2] 8a 9e [2] b5 82 }

  condition:
    any of them
}