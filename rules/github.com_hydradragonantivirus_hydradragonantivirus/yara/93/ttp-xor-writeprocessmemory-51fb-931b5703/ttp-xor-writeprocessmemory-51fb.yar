rule TTP_XOR_WriteProcessMemory_51fb {
  strings:
    $key_51fb = { 06 89 [2] 34 ab [2] 32 9e [2] 1c 9e [2] 23 82 }

  condition:
    any of them
}