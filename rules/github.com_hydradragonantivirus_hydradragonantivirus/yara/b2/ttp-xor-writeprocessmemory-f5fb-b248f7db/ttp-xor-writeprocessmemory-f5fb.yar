rule TTP_XOR_WriteProcessMemory_f5fb {
  strings:
    $key_f5fb = { a2 89 [2] 90 ab [2] 96 9e [2] b8 9e [2] 87 82 }

  condition:
    any of them
}