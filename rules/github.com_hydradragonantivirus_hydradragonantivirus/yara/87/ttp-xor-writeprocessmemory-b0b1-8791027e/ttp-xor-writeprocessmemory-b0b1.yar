rule TTP_XOR_WriteProcessMemory_b0b1 {
  strings:
    $key_b0b1 = { e7 c3 [2] d5 e1 [2] d3 d4 [2] fd d4 [2] c2 c8 }

  condition:
    any of them
}