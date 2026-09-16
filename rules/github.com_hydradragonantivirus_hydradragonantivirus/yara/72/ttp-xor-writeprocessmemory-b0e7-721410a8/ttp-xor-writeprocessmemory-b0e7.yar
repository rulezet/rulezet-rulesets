rule TTP_XOR_WriteProcessMemory_b0e7 {
  strings:
    $key_b0e7 = { e7 95 [2] d5 b7 [2] d3 82 [2] fd 82 [2] c2 9e }

  condition:
    any of them
}