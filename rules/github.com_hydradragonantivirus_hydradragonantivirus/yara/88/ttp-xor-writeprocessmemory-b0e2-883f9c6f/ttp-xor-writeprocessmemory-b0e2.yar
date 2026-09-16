rule TTP_XOR_WriteProcessMemory_b0e2 {
  strings:
    $key_b0e2 = { e7 90 [2] d5 b2 [2] d3 87 [2] fd 87 [2] c2 9b }

  condition:
    any of them
}