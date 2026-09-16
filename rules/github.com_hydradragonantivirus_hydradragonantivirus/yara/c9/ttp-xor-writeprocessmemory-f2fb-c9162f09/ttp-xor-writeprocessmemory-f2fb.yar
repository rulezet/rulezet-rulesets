rule TTP_XOR_WriteProcessMemory_f2fb {
  strings:
    $key_f2fb = { a5 89 [2] 97 ab [2] 91 9e [2] bf 9e [2] 80 82 }

  condition:
    any of them
}