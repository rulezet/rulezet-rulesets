rule TTP_XOR_WriteProcessMemory_b0d1 {
  strings:
    $key_b0d1 = { e7 a3 [2] d5 81 [2] d3 b4 [2] fd b4 [2] c2 a8 }

  condition:
    any of them
}