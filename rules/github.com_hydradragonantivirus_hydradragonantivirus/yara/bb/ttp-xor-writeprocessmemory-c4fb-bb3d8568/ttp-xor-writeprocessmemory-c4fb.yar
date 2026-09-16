rule TTP_XOR_WriteProcessMemory_c4fb {
  strings:
    $key_c4fb = { 93 89 [2] a1 ab [2] a7 9e [2] 89 9e [2] b6 82 }

  condition:
    any of them
}