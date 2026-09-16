rule TTP_XOR_WriteProcessMemory_71fb {
  strings:
    $key_71fb = { 26 89 [2] 14 ab [2] 12 9e [2] 3c 9e [2] 03 82 }

  condition:
    any of them
}