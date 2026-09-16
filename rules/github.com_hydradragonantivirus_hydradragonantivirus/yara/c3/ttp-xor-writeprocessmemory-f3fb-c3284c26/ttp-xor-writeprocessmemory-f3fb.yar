rule TTP_XOR_WriteProcessMemory_f3fb {
  strings:
    $key_f3fb = { a4 89 [2] 96 ab [2] 90 9e [2] be 9e [2] 81 82 }

  condition:
    any of them
}