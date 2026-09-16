rule TTP_XOR_WriteProcessMemory_72fb {
  strings:
    $key_72fb = { 25 89 [2] 17 ab [2] 11 9e [2] 3f 9e [2] 00 82 }

  condition:
    any of them
}