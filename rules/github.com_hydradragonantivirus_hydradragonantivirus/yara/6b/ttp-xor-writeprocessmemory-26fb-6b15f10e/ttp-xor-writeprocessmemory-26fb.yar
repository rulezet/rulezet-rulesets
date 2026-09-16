rule TTP_XOR_WriteProcessMemory_26fb {
  strings:
    $key_26fb = { 71 89 [2] 43 ab [2] 45 9e [2] 6b 9e [2] 54 82 }

  condition:
    any of them
}