rule TTP_XOR_WriteProcessMemory_39fb {
  strings:
    $key_39fb = { 6e 89 [2] 5c ab [2] 5a 9e [2] 74 9e [2] 4b 82 }

  condition:
    any of them
}