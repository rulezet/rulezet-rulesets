rule TTP_XOR_WriteProcessMemory_a0a1 {
  strings:
    $key_a0a1 = { f7 d3 [2] c5 f1 [2] c3 c4 [2] ed c4 [2] d2 d8 }

  condition:
    any of them
}