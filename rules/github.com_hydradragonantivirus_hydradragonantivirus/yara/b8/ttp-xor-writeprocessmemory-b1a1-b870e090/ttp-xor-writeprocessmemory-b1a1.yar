rule TTP_XOR_WriteProcessMemory_b1a1 {
  strings:
    $key_b1a1 = { e6 d3 [2] d4 f1 [2] d2 c4 [2] fc c4 [2] c3 d8 }

  condition:
    any of them
}