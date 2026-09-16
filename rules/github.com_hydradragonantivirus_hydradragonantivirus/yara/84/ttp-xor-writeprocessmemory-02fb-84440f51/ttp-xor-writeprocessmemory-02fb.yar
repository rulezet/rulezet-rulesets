rule TTP_XOR_WriteProcessMemory_02fb {
  strings:
    $key_02fb = { 55 89 [2] 67 ab [2] 61 9e [2] 4f 9e [2] 70 82 }

  condition:
    any of them
}