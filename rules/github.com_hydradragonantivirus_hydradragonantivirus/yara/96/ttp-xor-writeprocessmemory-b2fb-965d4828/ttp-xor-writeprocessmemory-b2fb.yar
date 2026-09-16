rule TTP_XOR_WriteProcessMemory_b2fb {
  strings:
    $key_b2fb = { e5 89 [2] d7 ab [2] d1 9e [2] ff 9e [2] c0 82 }

  condition:
    any of them
}