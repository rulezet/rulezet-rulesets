rule TTP_XOR_WriteProcessMemory_a1fb {
  strings:
    $key_a1fb = { f6 89 [2] c4 ab [2] c2 9e [2] ec 9e [2] d3 82 }

  condition:
    any of them
}