rule TTP_XOR_WriteProcessMemory_a2a1 {
  strings:
    $key_a2a1 = { f5 d3 [2] c7 f1 [2] c1 c4 [2] ef c4 [2] d0 d8 }

  condition:
    any of them
}