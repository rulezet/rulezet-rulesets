rule TTP_XOR_WriteProcessMemory_b0d6 {
  strings:
    $key_b0d6 = { e7 a4 [2] d5 86 [2] d3 b3 [2] fd b3 [2] c2 af }

  condition:
    any of them
}