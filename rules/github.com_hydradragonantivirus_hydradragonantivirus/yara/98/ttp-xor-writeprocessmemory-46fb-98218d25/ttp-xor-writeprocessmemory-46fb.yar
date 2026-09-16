rule TTP_XOR_WriteProcessMemory_46fb {
  strings:
    $key_46fb = { 11 89 [2] 23 ab [2] 25 9e [2] 0b 9e [2] 34 82 }

  condition:
    any of them
}