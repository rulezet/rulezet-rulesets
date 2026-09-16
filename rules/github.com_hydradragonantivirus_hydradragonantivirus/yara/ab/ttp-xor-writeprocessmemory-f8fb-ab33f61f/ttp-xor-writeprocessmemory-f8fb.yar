rule TTP_XOR_WriteProcessMemory_f8fb {
  strings:
    $key_f8fb = { af 89 [2] 9d ab [2] 9b 9e [2] b5 9e [2] 8a 82 }

  condition:
    any of them
}