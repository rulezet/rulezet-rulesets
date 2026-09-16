rule TTP_XOR_WriteProcessMemory_68fb {
  strings:
    $key_68fb = { 3f 89 [2] 0d ab [2] 0b 9e [2] 25 9e [2] 1a 82 }

  condition:
    any of them
}