rule TTP_XOR_WriteProcessMemory_05fb {
  strings:
    $key_05fb = { 52 89 [2] 60 ab [2] 66 9e [2] 48 9e [2] 77 82 }

  condition:
    any of them
}