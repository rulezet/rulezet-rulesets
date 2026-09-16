rule TTP_XOR_WriteProcessMemory_d5fb {
  strings:
    $key_d5fb = { 82 89 [2] b0 ab [2] b6 9e [2] 98 9e [2] a7 82 }

  condition:
    any of them
}