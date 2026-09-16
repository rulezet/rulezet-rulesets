rule TTP_XOR_WriteProcessMemory_e5fb {
  strings:
    $key_e5fb = { b2 89 [2] 80 ab [2] 86 9e [2] a8 9e [2] 97 82 }

  condition:
    any of them
}