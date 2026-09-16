rule TTP_XOR_WriteProcessMemory_b6fb {
  strings:
    $key_b6fb = { e1 89 [2] d3 ab [2] d5 9e [2] fb 9e [2] c4 82 }

  condition:
    any of them
}