rule TTP_XOR_WriteProcessMemory_a3a1 {
  strings:
    $key_a3a1 = { f4 d3 [2] c6 f1 [2] c0 c4 [2] ee c4 [2] d1 d8 }

  condition:
    any of them
}