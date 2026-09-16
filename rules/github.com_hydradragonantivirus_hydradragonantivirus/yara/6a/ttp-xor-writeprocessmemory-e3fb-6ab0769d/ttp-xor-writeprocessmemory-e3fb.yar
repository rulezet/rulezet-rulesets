rule TTP_XOR_WriteProcessMemory_e3fb {
  strings:
    $key_e3fb = { b4 89 [2] 86 ab [2] 80 9e [2] ae 9e [2] 91 82 }

  condition:
    any of them
}