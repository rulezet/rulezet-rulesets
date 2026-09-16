rule TTP_XOR_WriteProcessMemory_78fb {
  strings:
    $key_78fb = { 2f 89 [2] 1d ab [2] 1b 9e [2] 35 9e [2] 0a 82 }

  condition:
    any of them
}