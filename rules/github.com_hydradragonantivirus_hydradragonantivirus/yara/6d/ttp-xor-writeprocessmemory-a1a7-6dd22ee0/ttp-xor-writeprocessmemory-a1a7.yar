rule TTP_XOR_WriteProcessMemory_a1a7 {
  strings:
    $key_a1a7 = { f6 d5 [2] c4 f7 [2] c2 c2 [2] ec c2 [2] d3 de }

  condition:
    any of them
}