rule TTP_XOR_WriteProcessMemory_a1b0 {
  strings:
    $key_a1b0 = { f6 c2 [2] c4 e0 [2] c2 d5 [2] ec d5 [2] d3 c9 }

  condition:
    any of them
}