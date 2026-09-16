rule TTP_XOR_WriteProcessMemory_49fb {
  strings:
    $key_49fb = { 1e 89 [2] 2c ab [2] 2a 9e [2] 04 9e [2] 3b 82 }

  condition:
    any of them
}