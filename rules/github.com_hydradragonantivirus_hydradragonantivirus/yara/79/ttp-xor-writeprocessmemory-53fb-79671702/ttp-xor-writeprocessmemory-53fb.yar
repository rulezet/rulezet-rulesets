rule TTP_XOR_WriteProcessMemory_53fb {
  strings:
    $key_53fb = { 04 89 [2] 36 ab [2] 30 9e [2] 1e 9e [2] 21 82 }

  condition:
    any of them
}