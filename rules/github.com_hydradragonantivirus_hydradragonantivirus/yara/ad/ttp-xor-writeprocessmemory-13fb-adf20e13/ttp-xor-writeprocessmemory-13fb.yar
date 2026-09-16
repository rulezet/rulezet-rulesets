rule TTP_XOR_WriteProcessMemory_13fb {
  strings:
    $key_13fb = { 44 89 [2] 76 ab [2] 70 9e [2] 5e 9e [2] 61 82 }

  condition:
    any of them
}