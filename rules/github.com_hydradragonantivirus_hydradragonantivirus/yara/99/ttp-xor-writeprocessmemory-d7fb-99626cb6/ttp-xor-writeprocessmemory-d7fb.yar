rule TTP_XOR_WriteProcessMemory_d7fb {
  strings:
    $key_d7fb = { 80 89 [2] b2 ab [2] b4 9e [2] 9a 9e [2] a5 82 }

  condition:
    any of them
}