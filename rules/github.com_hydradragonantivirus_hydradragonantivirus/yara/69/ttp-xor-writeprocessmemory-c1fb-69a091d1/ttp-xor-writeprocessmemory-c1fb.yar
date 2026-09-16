rule TTP_XOR_WriteProcessMemory_c1fb {
  strings:
    $key_c1fb = { 96 89 [2] a4 ab [2] a2 9e [2] 8c 9e [2] b3 82 }

  condition:
    any of them
}