rule TTP_XOR_WriteProcessMemory_b0e0 {
  strings:
    $key_b0e0 = { e7 92 [2] d5 b0 [2] d3 85 [2] fd 85 [2] c2 99 }

  condition:
    any of them
}