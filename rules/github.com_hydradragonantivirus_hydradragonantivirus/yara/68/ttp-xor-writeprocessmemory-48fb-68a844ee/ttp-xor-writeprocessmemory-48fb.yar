rule TTP_XOR_WriteProcessMemory_48fb {
  strings:
    $key_48fb = { 1f 89 [2] 2d ab [2] 2b 9e [2] 05 9e [2] 3a 82 }

  condition:
    any of them
}