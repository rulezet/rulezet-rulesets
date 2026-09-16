rule TTP_XOR_WriteProcessMemory_c0fb {
  strings:
    $key_c0fb = { 97 89 [2] a5 ab [2] a3 9e [2] 8d 9e [2] b2 82 }

  condition:
    any of them
}