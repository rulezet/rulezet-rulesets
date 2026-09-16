rule TTP_XOR_WriteProcessMemory_60fb {
  strings:
    $key_60fb = { 37 89 [2] 05 ab [2] 03 9e [2] 2d 9e [2] 12 82 }

  condition:
    any of them
}