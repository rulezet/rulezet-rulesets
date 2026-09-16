rule TTP_XOR_WriteProcessMemory_34fb {
  strings:
    $key_34fb = { 63 89 [2] 51 ab [2] 57 9e [2] 79 9e [2] 46 82 }

  condition:
    any of them
}