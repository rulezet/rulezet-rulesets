rule TTP_XOR_WriteProcessMemory_c3fb {
  strings:
    $key_c3fb = { 94 89 [2] a6 ab [2] a0 9e [2] 8e 9e [2] b1 82 }

  condition:
    any of them
}