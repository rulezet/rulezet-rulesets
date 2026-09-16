rule TTP_XOR_WriteProcessMemory_28fb {
  strings:
    $key_28fb = { 7f 89 [2] 4d ab [2] 4b 9e [2] 65 9e [2] 5a 82 }

  condition:
    any of them
}