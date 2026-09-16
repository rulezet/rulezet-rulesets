rule TTP_XOR_WriteProcessMemory_b0d2 {
  strings:
    $key_b0d2 = { e7 a0 [2] d5 82 [2] d3 b7 [2] fd b7 [2] c2 ab }

  condition:
    any of them
}