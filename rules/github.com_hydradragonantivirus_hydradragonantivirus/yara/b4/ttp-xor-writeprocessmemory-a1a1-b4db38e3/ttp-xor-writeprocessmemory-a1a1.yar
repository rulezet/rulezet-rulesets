rule TTP_XOR_WriteProcessMemory_a1a1 {
  strings:
    $key_a1a1 = { f6 d3 [2] c4 f1 [2] c2 c4 [2] ec c4 [2] d3 d8 }

  condition:
    any of them
}