rule TTP_XOR_WriteProcessMemory_c2fb {
  strings:
    $key_c2fb = { 95 89 [2] a7 ab [2] a1 9e [2] 8f 9e [2] b0 82 }

  condition:
    any of them
}