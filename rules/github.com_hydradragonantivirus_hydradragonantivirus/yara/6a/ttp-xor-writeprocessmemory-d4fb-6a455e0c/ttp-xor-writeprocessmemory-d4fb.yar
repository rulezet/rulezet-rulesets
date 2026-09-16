rule TTP_XOR_WriteProcessMemory_d4fb {
  strings:
    $key_d4fb = { 83 89 [2] b1 ab [2] b7 9e [2] 99 9e [2] a6 82 }

  condition:
    any of them
}