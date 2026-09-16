rule TTP_XOR_WriteProcessMemory_a1a0 {
  strings:
    $key_a1a0 = { f6 d2 [2] c4 f0 [2] c2 c5 [2] ec c5 [2] d3 d9 }

  condition:
    any of them
}