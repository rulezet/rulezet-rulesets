rule TTP_XOR_WriteProcessMemory_55fb {
  strings:
    $key_55fb = { 02 89 [2] 30 ab [2] 36 9e [2] 18 9e [2] 27 82 }

  condition:
    any of them
}