rule TTP_XOR_WriteProcessMemory_66fb {
  strings:
    $key_66fb = { 31 89 [2] 03 ab [2] 05 9e [2] 2b 9e [2] 14 82 }

  condition:
    any of them
}