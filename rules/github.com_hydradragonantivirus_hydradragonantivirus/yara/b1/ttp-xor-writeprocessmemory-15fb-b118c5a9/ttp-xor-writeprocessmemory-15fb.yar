rule TTP_XOR_WriteProcessMemory_15fb {
  strings:
    $key_15fb = { 42 89 [2] 70 ab [2] 76 9e [2] 58 9e [2] 67 82 }

  condition:
    any of them
}