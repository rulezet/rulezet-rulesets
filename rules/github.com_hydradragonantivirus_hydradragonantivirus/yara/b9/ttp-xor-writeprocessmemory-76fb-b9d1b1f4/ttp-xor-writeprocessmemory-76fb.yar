rule TTP_XOR_WriteProcessMemory_76fb {
  strings:
    $key_76fb = { 21 89 [2] 13 ab [2] 15 9e [2] 3b 9e [2] 04 82 }

  condition:
    any of them
}