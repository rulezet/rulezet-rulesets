rule TTP_XOR_WriteProcessMemory_f1fb {
  strings:
    $key_f1fb = { a6 89 [2] 94 ab [2] 92 9e [2] bc 9e [2] 83 82 }

  condition:
    any of them
}