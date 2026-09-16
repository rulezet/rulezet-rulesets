rule TTP_XOR_WriteProcessMemory_09fb {
  strings:
    $key_09fb = { 5e 89 [2] 6c ab [2] 6a 9e [2] 44 9e [2] 7b 82 }

  condition:
    any of them
}