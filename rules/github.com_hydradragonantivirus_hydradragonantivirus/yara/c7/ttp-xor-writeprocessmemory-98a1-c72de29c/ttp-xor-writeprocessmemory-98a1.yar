rule TTP_XOR_WriteProcessMemory_98a1 {
  strings:
    $key_98a1 = { cf d3 [2] fd f1 [2] fb c4 [2] d5 c4 [2] ea d8 }

  condition:
    any of them
}