rule TTP_XOR_WriteProcessMemory_04fb {
  strings:
    $key_04fb = { 53 89 [2] 61 ab [2] 67 9e [2] 49 9e [2] 76 82 }

  condition:
    any of them
}