rule TTP_XOR_WriteProcessMemory_73fb {
  strings:
    $key_73fb = { 24 89 [2] 16 ab [2] 10 9e [2] 3e 9e [2] 01 82 }

  condition:
    any of them
}