rule TTP_XOR_WriteProcessMemory_11fb {
  strings:
    $key_11fb = { 46 89 [2] 74 ab [2] 72 9e [2] 5c 9e [2] 63 82 }

  condition:
    any of them
}