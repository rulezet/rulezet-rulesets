rule TTP_XOR_WriteProcessMemory_41fb {
  strings:
    $key_41fb = { 16 89 [2] 24 ab [2] 22 9e [2] 0c 9e [2] 33 82 }

  condition:
    any of them
}