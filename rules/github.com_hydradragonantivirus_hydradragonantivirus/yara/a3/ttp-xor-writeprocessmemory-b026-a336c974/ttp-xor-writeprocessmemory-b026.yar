rule TTP_XOR_WriteProcessMemory_b026 {
  strings:
    $key_b026 = { e7 54 [2] d5 76 [2] d3 43 [2] fd 43 [2] c2 5f }

  condition:
    any of them
}