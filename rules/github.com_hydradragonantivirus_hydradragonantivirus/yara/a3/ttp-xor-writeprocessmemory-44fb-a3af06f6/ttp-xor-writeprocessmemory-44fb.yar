rule TTP_XOR_WriteProcessMemory_44fb {
  strings:
    $key_44fb = { 13 89 [2] 21 ab [2] 27 9e [2] 09 9e [2] 36 82 }

  condition:
    any of them
}